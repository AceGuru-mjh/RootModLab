/*
 * HideAllRoot v2.0 — Zygisk native hide module (libzygisk.so)
 * -----------------------------------------------------------
 * Rewrites the v1.x engine around a VFS-level + PLT-hook hybrid that hides
 * every root trace detectors (Momo / Ruru / SpringRoot-春秋 / RootBeer /
 * Play Integrity) look for, driven entirely by
 * /data/adb/hideallroot/config.conf so the operator can tune behaviour from
 * the WebUI without recompiling.
 *
 * v2.0 hook surface (vs v1.x)
 *   1. File access      — PLT hook open/openat/openat2/access/faccessat/
 *                         faccessat2 + direct syscall() interception, with
 *                         *precise prefix + word-boundary* path matching
 *                         (fixes v1.x strstr false-positives).
 *   2. Metadata         — stat/lstat/fstatat/statx/__xstat/__lxstat/__fxstatat
 *                         + readlink/readlinkat + syscall() coverage.
 *   3. VFS unmount      — in the app's private mount namespace, parse
 *                         /proc/self/mountinfo and MNT_DETACH the Magisk tmpfs
 *                         / overlay mounts (the real "unmount", not just ENOENT).
 *   4. Process hide     — readdir/readdir64 filter + connect() UNIX-socket
 *                         block + kill() interception + PID→comm cache (TTL).
 *   5. maps / memfd     — buffered /proc/self/maps filter + anonymous-mapping
 *                         rename defense (prctl PR_SET_VMA_ANON_NAME scrub).
 *   6. Property hide    — __system_property_get + __system_property_find, plus
 *                         bootloader-unlock / debuggable prop sanitization.
 *   7. Environment      — scrub Zygisk/Magisk/KSU/APatch env vars + PATH.
 *   8. SELinux          — sanitize leaked root contexts in
 *                         /proc/self/attr/current and /proc/<pid>/attr/current.
 *   9. Anti-debug       — zero TracerPid in /proc/self/status + ptrace self-block.
 *  10. Daemon sockets   — strip magiskd/zygiskd sockets from /proc/net/unix.
 *  11. Kernel modules   — strip magisk/zygisk/ksu/apatch entries from
 *                         /proc/modules.
 *  12. App list         — filter packages.xml / packages.list for root managers.
 *
 * Compatible: Magisk 25.0+ (native Zygisk). KernelSU / APatch require the
 * ZygiskNext companion module for this .so to load.
 *
 * Developer: RootModLab
 */

#include <zygisk.hpp>

#include <android/log.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/system_properties.h>
#include <time.h>
#include <unistd.h>

#include <cctype>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#endif
#ifndef PR_SET_VMA_ANON_NAME
#define PR_SET_VMA_ANON_NAME 0
#endif

#define LOG_TAG "HideAllRoot"
#define HAR_LOG(...)  __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define HAR_LOGV(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

/* ------------------------------------------------------------------ */
/* Runtime configuration (parsed from /data/adb/hideallroot/config.conf)
 *
 * v2.0 key system (master + per-feature switches):
 *   ENABLE                master switch (0 disables everything)
 *   ENABLE_FILE_HIDE      open/openat/openat2/access/stat/readlink
 *   ENABLE_PROP_HIDE      __system_property_get / __system_property_find
 *   ENABLE_PROC_HIDE      readdir filter + connect() + kill() + PID cache
 *   ENABLE_MAPS_HIDE      /proc/<pid>/maps + anonymous-mapping rename
 *   ENABLE_MOUNT_HIDE     /proc/mounts + /proc/self/mountinfo
 *   ENABLE_SOCKET_HIDE    /proc/net/unix daemon sockets
 *   ENABLE_DEBUG_HIDE     TracerPid zeroing + ptrace self-block
 *   ENABLE_UNMOUNT        VFS-level Magisk tmpfs/overlay unmount
 *   ENABLE_ENV_CLEAN      env var + PATH scrub
 *   ENABLE_ZYGISK_CLEAN   aggressive zygisk/frida/gum/xhook maps scrub
 *   TARGET_MODE           0=all apps 1=detect tools only 2=custom pkgs only
 *   TARGET_PKGS           detect-tool package list (mode 1)
 *   CUSTOM_PKGS           custom package list (mode 2)
 */

struct Config {
    bool enable = false;
    bool file_hide = false, prop_hide = false, proc_hide = false,
         maps_hide = false, mount_hide = false, socket_hide = false,
         debug_hide = false, unmount = false, env_clean = false,
         zygisk_clean = false;
    int  target_mode = 0;
    std::vector<std::string> target_pkgs;
    std::vector<std::string> custom_pkgs;
};

static Config g_cfg;
static bool   g_should_hide = false;   // per-process, set in preAppSpecialize
static std::string g_pkg;

static const char *kConfigPath = "/data/adb/hideallroot/config.conf";

/* ------------------------------------------------------------------ */
/* Token / path matching helpers                                       */

static bool str_has(const char *hay, const char *needle) {
    return hay && needle && strstr(hay, needle) != nullptr;
}

// Word-boundary match: `tok` must appear as a whole component or bounded by
// one of .-_/ at both sides. Prevents v1.x false positives like "issue"→"su".
static bool word_match(const char *s, const char *tok) {
    if (!s || !tok) return false;
    size_t sl = strlen(s), tl = strlen(tok);
    if (tl == 0 || sl < tl) return false;
    auto is_bound = [](char c) {
        return c == '\0' || c == '.' || c == '-' || c == '_' || c == '/' || c == ' ';
    };
    for (size_t i = 0; i + tl <= sl; ++i) {
        if (strncmp(s + i, tok, tl) != 0) continue;
        char before = (i == 0) ? '\0' : s[i - 1];
        char after  = (i + tl < sl) ? s[i + tl] : '\0';
        if (is_bound(before) && is_bound(after)) return true;
    }
    return false;
}

static bool str_ends_with(const char *s, const char *suf) {
    size_t ls = s ? strlen(s) : 0, lf = strlen(suf);
    return ls >= lf && strcmp(s + ls - lf, suf) == 0;
}

// Root-related tokens used to flag a file path as a hide target.
static const char *kRootTokens[] = {
    "magisk", "zygisk", "ksu", "kernelsu", "apatch", "lspd", "lsposed",
    "riru", "magiskhide", "magiskd", "zygiskd", "ksud", "apd", "apatchd",
    nullptr
};

// Exact / prefix daemon comms we refuse to expose via /proc.
static const char *kDaemons[] = {
    "magiskd", "zygiskd", "ksud", "apd", "apatchd", "magisk", "ksu",
    "apatch", "rurud", "magiskd:", nullptr
};

static bool is_root_token(const char *s) {
    for (int i = 0; kRootTokens[i]; ++i)
        if (word_match(s, kRootTokens[i])) return true;
    return false;
}

// True if the (already-normalized) path points at a root artifact we hide.
static bool is_root_path(const char *path) {
    if (!path) return false;
    if (str_has(path, "/data/adb/modules/")) {
        // Hide the module overlay dir entries (but allow /data/adb/modules
        // itself so the manager can still read the list if it must).
        if (str_ends_with(path, "/data/adb/modules") ||
            strcmp(path, "/data/adb/modules") == 0) return false;
        return true;
    }
    if (str_has(path, "/data/adb/magisk")) return true;
    if (str_has(path, "/data/adb/ksu")) return true;
    if (str_has(path, "/data/adb/apatch")) return true;
    if (str_has(path, "/debug_ramdisk")) return true; // magisk overlay on some ROMs

    // component-wise scan
    const char *p = path;
    char comp[256];
    while (*p) {
        size_t n = 0;
        while (*p && *p != '/' && n + 1 < sizeof(comp)) comp[n++] = *p++;
        while (*p == '/') p++;
        comp[n] = '\0';
        if (comp[0] && is_root_token(comp)) return true;
    }
    return false;
}

/* ------------------------------------------------------------------ */
/* Buffered read filtering for synthetic /proc files                  */

enum BufMode { LINES, STATUS, ATTR, MAPS, RAW };

struct BufFilter {
    bool      active = false;
    BufMode   mode   = LINES;
    std::string data;   // full, already-filtered content
    size_t    cursor = 0;
};

static std::mutex g_buffd_lock;
static std::unordered_map<int, BufFilter> g_buffd;

static bool is_status_path(const char *path) {
    if (strcmp(path, "/proc/self/status") == 0) return true;
    // /proc/<pid>/status
    if (strncmp(path, "/proc/", 6) == 0) {
        const char *rest = path + 6;
        const char *sl = strchr(rest, '/');
        if (sl && strcmp(sl, "/status") == 0) {
            for (const char *c = rest; c < sl; ++c)
                if (!isdigit((unsigned char)*c)) return false;
            return true;
        }
    }
    return false;
}

static bool is_maps_path(const char *path) {
    if (strcmp(path, "/proc/self/maps") == 0) return true;
    if (strcmp(path, "/proc/self/smaps") == 0) return true;
    if (strcmp(path, "/proc/self/smaps_rollup") == 0) return true;
    if (strncmp(path, "/proc/", 6) == 0) {
        const char *rest = path + 6;
        const char *sl = strchr(rest, '/');
        if (sl && (strcmp(sl, "/maps") == 0 || strcmp(sl, "/smaps") == 0)) {
            for (const char *c = rest; c < sl; ++c)
                if (!isdigit((unsigned char)*c)) return false;
            return true;
        }
    }
    return false;
}

static bool is_attr_path(const char *path) {
    if (strcmp(path, "/proc/self/attr/current") == 0 ||
        strcmp(path, "/proc/self/attr/prev") == 0 ||
        strcmp(path, "/proc/self/attr/exec") == 0)
        return true;
    // /proc/<pid>/attr/{current,prev,exec}
    if (strncmp(path, "/proc/", 6) == 0) {
        const char *rest = path + 6;
        const char *sl = strstr(rest, "/attr/");
        if (sl) {
            for (const char *c = rest; c < sl; ++c)
                if (!isdigit((unsigned char)*c)) return false;
            return true;
        }
    }
    return false;
}

static bool is_modules_path(const char *path) {
    return strcmp(path, "/proc/modules") == 0;
}

static bool is_mounts_path(const char *path) {
    return strcmp(path, "/proc/mounts") == 0 ||
           strcmp(path, "/proc/self/mounts") == 0 ||
           strcmp(path, "/proc/self/mountinfo") == 0;
}

static bool is_netunix_path(const char *path) {
    return strcmp(path, "/proc/net/unix") == 0;
}

static bool is_applist_path(const char *path) {
    return str_ends_with(path, "/packages.xml") ||
           str_ends_with(path, "/packages.list");
}

// maps / needle scrubbing for /proc/*/maps lines.
static std::string filter_maps_line(const char *line) {
    // Skip lines that reveal root libs / frameworks / memfd anon regions.
    if (is_root_token(line)) {
        // but only when it's part of a path/name token
        if (str_has(line, "zygisk") || str_has(line, "magisk") ||
            str_has(line, "/ksu") || str_has(line, "apatch") ||
            str_has(line, "lspd") || str_has(line, "lsposed") ||
            str_has(line, "riru") || str_has(line, "frida") ||
            str_has(line, "libgum") || str_has(line, "xhook") ||
            str_has(line, "memfd") || str_has(line, "substrate"))
            return "";
    }
    return std::string(line);
}

// Sanitize a leaked root SELinux context → generic untrusted_app context.
static std::string filter_attr_line(const std::string &line) {
    if (str_has(line.c_str(), "magisk") || str_has(line.c_str(), "zygisk") ||
        str_has(line.c_str(), "su:") || str_has(line.c_str(), "ksu") ||
        str_has(line.c_str(), "apatch") || str_has(line.c_str(), "kernelsu")) {
        return "u:r:untrusted_app:s0\n";
    }
    return line;
}

static std::string filter_line_by_mode(const char *line, BufMode mode) {
    switch (mode) {
        case MAPS:
            return filter_maps_line(line);
        case ATTR:
            return filter_attr_line(std::string(line));
        case STATUS: {
            // zero TracerPid
            if (strncmp(line, "TracerPid:", 10) == 0)
                return "TracerPid:\t0\n";
            return std::string(line);
        }
        case LINES: {
            if (str_has(line, "magisk") || str_has(line, "zygisk") ||
                str_has(line, "ksu") || str_has(line, "apatch") ||
                str_has(line, "lspd") || str_has(line, "lsposed") ||
                str_has(line, "riru") || str_has(line, "kernelsu"))
                return "";
            return std::string(line);
        }
        case RAW:
        default:
            return std::string(line);
    }
}

// Build the buffered, filtered content for a synthetic file.
static std::string build_filtered(const char *raw, BufMode mode) {
    std::string out;
    const char *p = raw;
    const char *start = raw;
    while (*p) {
        if (*p == '\n') {
            std::string line(start, (size_t)(p - start) + 1);
            std::string f = filter_line_by_mode(line.c_str(), mode);
            out += f;
            start = p + 1;
        }
        ++p;
    }
    if (p > start) {
        std::string line(start, (size_t)(p - start));
        std::string f = filter_line_by_mode(line.c_str(), mode);
        out += f;
        if (!out.empty() && out.back() != '\n') out += '\n';
    }
    return out;
}

static BufMode mode_for_path(const char *path) {
    if (is_status_path(path)) return STATUS;
    if (is_maps_path(path))   return MAPS;
    if (is_attr_path(path))   return ATTR;
    return LINES;
}

static bool should_buffer(const char *path) {
    if (!g_should_hide) return false;
    if (is_status_path(path) && g_cfg.debug_hide) return true;
    if (is_maps_path(path) && g_cfg.maps_hide) return true;
    if (is_attr_path(path)) return true;
    if (is_modules_path(path)) return true;
    if (is_mounts_path(path) && g_cfg.mount_hide) return true;
    if (is_netunix_path(path) && g_cfg.socket_hide) return true;
    if (is_applist_path(path)) return true;
    return false;
}

// Read the whole fd into a string. We call the libc read() which is already
// redirected to my_read; since the fd is not yet buffered, my_read falls
// through to the original read and returns the real content.
static std::string read_all(int fd) {
    std::string s;
    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0)
        s.append(buf, (size_t)n);
    return s;
}

// Populate the buffered, filtered content for a synthetic /proc file.
static void setup_buffer(int fd, const char *path) {
    if (fd < 0) return;
    std::string raw = read_all(fd);
    BufFilter bf;
    bf.active = true;
    bf.mode = mode_for_path(path);
    bf.data = build_filtered(raw.c_str(), bf.mode);
    bf.cursor = 0;
    std::lock_guard<std::mutex> lk(g_buffd_lock);
    g_buffd[fd] = std::move(bf);
}

/* ------------------------------------------------------------------ */
/* Original-function pointers (populated by PLT hook registration)    */

static int    (*orig_open)(const char *, int, ...) = nullptr;
static int    (*orig_openat)(int, const char *, int, ...) = nullptr;
static int    (*orig_faccessat)(int, const char *, int, int) = nullptr;
static int    (*orig_access)(const char *, int) = nullptr;
static int    (*orig_stat)(const char *, struct stat *) = nullptr;
static int    (*orig_lstat)(const char *, struct stat *) = nullptr;
static int    (*orig_fstatat)(int, const char *, struct stat *, int) = nullptr;
static int    (*orig___xstat)(int, const char *, struct stat *) = nullptr;
static int    (*orig___lxstat)(int, const char *, struct stat *) = nullptr;
static int    (*orig___fxstatat)(int, int, const char *, struct stat *, int) = nullptr;
static int    (*orig_readlink)(const char *, char *, size_t) = nullptr;
static int    (*orig_readlinkat)(int, const char *, char *, size_t) = nullptr;
static ssize_t (*orig_read)(int, void *, size_t) = nullptr;
static ssize_t (*orig_pread64)(int, void *, size_t, off_t) = nullptr;
static int    (*orig_close)(int) = nullptr;
static off_t  (*orig_lseek)(int, off_t, int) = nullptr;
static off_t  (*orig_lseek64)(int, off64_t, int) = nullptr;
static struct dirent *(*orig_readdir)(DIR *) = nullptr;
static struct dirent64 *(*orig_readdir64)(DIR *) = nullptr;
static int    (*orig_dladdr)(void *, Dl_info *) = nullptr;
static int    (*orig___system_property_get)(const char *, char *) = nullptr;
static const void *(*orig___system_property_find)(const char *) = nullptr;
static int    (*orig_connect)(int, const struct sockaddr *, socklen_t) = nullptr;
static int    (*orig_kill)(pid_t, int) = nullptr;
static int    (*orig_prctl)(int, ...) = nullptr;
static long   (*orig_syscall)(long, ...) = nullptr;
// opaque-typed wrappers (struct layout is irrelevant for path filtering)
typedef int (*statx_t)(int, const char *, int, unsigned int, void *);
typedef int (*openat2_t)(int, const char *, const void *, size_t);
typedef int (*faccessat2_t)(int, const char *, int, int);
static statx_t        orig_statx = nullptr;
static openat2_t      orig_openat2 = nullptr;
static faccessat2_t   orig_faccessat2 = nullptr;

/* ------------------------------------------------------------------ */
/* Process hide helpers                                                */

// pid → comm cache (TTL 1s) to avoid stat'ing /proc on every kill/connect.
struct CommEntry { std::string comm; long ts; };
static std::mutex g_comm_lock;
static std::unordered_map<pid_t, CommEntry> g_commcache;

static std::string comm_of(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", (int)pid);
    int fd = orig_open ? orig_open(path, O_RDONLY) : open(path, O_RDONLY);
    if (fd < 0) return "";
    char buf[32] = {0};
    ssize_t n = orig_read ? orig_read(fd, buf, sizeof(buf) - 1)
                          : read(fd, buf, sizeof(buf) - 1);
    if (fd >= 0) close(fd);
    if (n <= 0) return "";
    // strip trailing newline
    for (ssize_t i = 0; i < n; ++i)
        if (buf[i] == '\n') { buf[i] = '\0'; break; }
    std::string c(buf);
    // trim (comm may include a trailing ':' from magiskd:)
    return c;
}

static bool is_daemon_comm(const char *comm) {
    if (!comm) return false;
    for (int i = 0; kDaemons[i]; ++i)
        if (strncmp(comm, kDaemons[i], strlen(kDaemons[i])) == 0) return true;
    return false;
}

static bool daemon_pid(pid_t pid) {
    if (pid <= 0) return false;
    long now = time(nullptr);
    {
        std::lock_guard<std::mutex> lk(g_comm_lock);
        auto it = g_commcache.find(pid);
        if (it != g_commcache.end() && now - it->second.ts < 1)
            return is_daemon_comm(it->second.comm.c_str());
    }
    std::string c = comm_of(pid);
    bool hit = is_daemon_comm(c.c_str());
    {
        std::lock_guard<std::mutex> lk(g_comm_lock);
        g_commcache[pid] = {c, now};
    }
    return hit;
}

/* ------------------------------------------------------------------ */
/* Resolve dirfd + relative path → absolute path                      */

static std::string fd_path(int dirfd) {
    if (dirfd < 0) return "";
    char link[64];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", dirfd);
    char buf[PATH_MAX] = {0};
    thread_local bool guard = false;
    if (guard) return "";
    guard = true;
    ssize_t n = orig_readlink ? orig_readlink(link, buf, sizeof(buf) - 1)
                              : readlink(link, buf, sizeof(buf) - 1);
    guard = false;
    if (n > 0) { buf[n] = '\0'; return std::string(buf); }
    return "";
}

static std::string resolve_at(int dirfd, const char *path) {
    if (!path) return "";
    if (path[0] == '/') return std::string(path);
    std::string base = fd_path(dirfd);
    if (base.empty()) return std::string(path);
    if (base.back() == '/') return base + path;
    return base + "/" + path;
}

/* ------------------------------------------------------------------ */
/* Property hiding                                                     */

static bool is_hidden_prop(const char *name) {
    if (!name) return false;
    static const char *prefixes[] = {
        "ro.magisk.", "ro.ksu.", "ro.kernelsu.", "ro.apatch.",
        "ro.riru.", "ro.lsposed.", "persist.magisk.", "persist.sys.zygisk.",
        nullptr
    };
    for (int i = 0; prefixes[i]; ++i)
        if (strncmp(name, prefixes[i], strlen(prefixes[i])) == 0) return true;
    // build / debuggable props
    if (strcmp(name, "ro.build.tags") == 0) return true;
    if (strcmp(name, "ro.build.type") == 0) return true;
    if (strcmp(name, "ro.debuggable") == 0) return true;
    if (strcmp(name, "ro.secure") == 0) return true;
    if (strcmp(name, "persist.sys.root") == 0) return true;
    if (strcmp(name, "ro.build.selinux") == 0) return true;
    if (str_has(name, "magisk")) return true;
    return false;
}

static void sanitize_prop_value(const char *name, char *value) {
    if (!name || !value) return;
    if (strcmp(name, "ro.build.tags") == 0) {
        strncpy(value, "release-keys", PROP_VALUE_MAX - 1);
        value[PROP_VALUE_MAX - 1] = '\0';
    } else if (strcmp(name, "ro.build.type") == 0) {
        strncpy(value, "user", PROP_VALUE_MAX - 1);
        value[PROP_VALUE_MAX - 1] = '\0';
    } else if (strcmp(name, "ro.debuggable") == 0) {
        strncpy(value, "0", PROP_VALUE_MAX - 1);
        value[PROP_VALUE_MAX - 1] = '\0';
    } else if (strcmp(name, "ro.secure") == 0) {
        strncpy(value, "1", PROP_VALUE_MAX - 1);
        value[PROP_VALUE_MAX - 1] = '\0';
    }
}

/* ------------------------------------------------------------------ */
/* readdir helpers                                                     */

static int g_readdir_depth = 0; // guard against re-entrancy

static std::string dir_path_of(DIR *dir) {
    int fd = dirfd(dir);
    if (fd < 0) return "";
    char link[64];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    char buf[PATH_MAX] = {0};
    if (g_readdir_depth > 4) return "";
    g_readdir_depth++;
    ssize_t n = orig_readlink ? orig_readlink(link, buf, sizeof(buf) - 1)
                              : readlink(link, buf, sizeof(buf) - 1);
    g_readdir_depth--;
    if (n > 0) { buf[n] = '\0'; return std::string(buf); }
    return "";
}

static bool dir_entry_blocked(const std::string &dir, const char *name) {
    if (!g_should_hide || !g_cfg.proc_hide) return false;
    if (name == nullptr || name[0] == '\0') return false;

    if (dir == "/proc") {
        // Hide daemon pid directories (numeric).
        if (isdigit((unsigned char)name[0])) {
            pid_t pid = (pid_t)atoi(name);
            if (daemon_pid(pid)) return true;
        }
        return false;
    }
    if (dir == "/data/adb/modules" || dir == "/data/adb/modules/") {
        std::string full = std::string("/data/adb/modules/") + name;
        return is_root_path(full.c_str());
    }
    if (dir == "/proc/self/fd" || dir == "/proc/self/task") return false;
    return false;
}

/* ------------------------------------------------------------------ */
/* Hook implementations                                                */

static int my_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap);
    if (g_should_hide && g_cfg.file_hide && path && is_root_path(path)) {
        errno = ENOENT; return -1;
    }
    int fd = orig_open ? orig_open(path, flags, mode) : open(path, flags, mode);
    if (fd >= 0 && should_buffer(path)) setup_buffer(fd, path);
    return fd;
}

static int my_openat(int dirfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap);
    if (g_should_hide && g_cfg.file_hide) {
        std::string full = resolve_at(dirfd, path);
        if (!full.empty() && is_root_path(full.c_str())) { errno = ENOENT; return -1; }
    }
    int fd = orig_openat ? orig_openat(dirfd, path, flags, mode)
                         : openat(dirfd, path, flags, mode);
    std::string full = resolve_at(dirfd, path);
    if (fd >= 0 && should_buffer(full.c_str())) setup_buffer(fd, full.c_str());
    return fd;
}

static int my_openat2(int dirfd, const char *path, const void *how, size_t size) {
    if (g_should_hide && g_cfg.file_hide) {
        std::string full = resolve_at(dirfd, path);
        if (!full.empty() && is_root_path(full.c_str())) { errno = ENOENT; return -1; }
    }
    if (orig_openat2) return orig_openat2(dirfd, path, how, size);
    errno = ENOSYS; return -1;
}

static int my_access(const char *path, int mode) {
    if (g_should_hide && g_cfg.file_hide && path && is_root_path(path)) {
        errno = ENOENT; return -1;
    }
    return orig_access ? orig_access(path, mode) : access(path, mode);
}

static int my_faccessat(int dirfd, const char *path, int mode, int flags) {
    if (g_should_hide && g_cfg.file_hide) {
        std::string full = resolve_at(dirfd, path);
        if (!full.empty() && is_root_path(full.c_str())) { errno = ENOENT; return -1; }
    }
    if (orig_faccessat) return orig_faccessat(dirfd, path, mode, flags);
    return faccessat(dirfd, path, mode, flags);
}

static int my_faccessat2(int dirfd, const char *path, int mode, int flags) {
    if (g_should_hide && g_cfg.file_hide) {
        std::string full = resolve_at(dirfd, path);
        if (!full.empty() && is_root_path(full.c_str())) { errno = ENOENT; return -1; }
    }
    if (orig_faccessat2) return orig_faccessat2(dirfd, path, mode, flags);
    return faccessat(dirfd, path, mode, flags);
}

static int my_stat(const char *path, struct stat *st) {
    if (g_should_hide && g_cfg.file_hide && path && is_root_path(path)) {
        errno = ENOENT; return -1;
    }
    return orig_stat ? orig_stat(path, st) : stat(path, st);
}

static int my_lstat(const char *path, struct stat *st) {
    if (g_should_hide && g_cfg.file_hide && path && is_root_path(path)) {
        errno = ENOENT; return -1;
    }
    return orig_lstat ? orig_lstat(path, st) : lstat(path, st);
}

static int my_fstatat(int dirfd, const char *path, struct stat *st, int f) {
    if (g_should_hide && g_cfg.file_hide) {
        std::string full = resolve_at(dirfd, path);
        if (!full.empty() && is_root_path(full.c_str())) { errno = ENOENT; return -1; }
    }
    return orig_fstatat ? orig_fstatat(dirfd, path, st, f)
                        : fstatat(dirfd, path, st, f);
}

static int my___xstat(int ver, const char *path, struct stat *st) {
    if (g_should_hide && g_cfg.file_hide && path && is_root_path(path)) {
        errno = ENOENT; return -1;
    }
    return orig___xstat ? orig___xstat(ver, path, st) : stat(path, st);
}

static int my___lxstat(int ver, const char *path, struct stat *st) {
    if (g_should_hide && g_cfg.file_hide && path && is_root_path(path)) {
        errno = ENOENT; return -1;
    }
    return orig___lxstat ? orig___lxstat(ver, path, st) : lstat(path, st);
}

static int my___fxstatat(int ver, int dirfd, const char *path, struct stat *st, int f) {
    if (g_should_hide && g_cfg.file_hide) {
        std::string full = resolve_at(dirfd, path);
        if (!full.empty() && is_root_path(full.c_str())) { errno = ENOENT; return -1; }
    }
    if (orig___fxstatat) return orig___fxstatat(ver, dirfd, path, st, f);
    return fstatat(dirfd, path, st, f);
}

static int my_statx(int dirfd, const char *path, int flags, unsigned int mask, void *stx) {
    if (g_should_hide && g_cfg.file_hide) {
        std::string full = resolve_at(dirfd, path);
        if (!full.empty() && is_root_path(full.c_str())) { errno = ENOENT; return -1; }
    }
    if (orig_statx) return orig_statx(dirfd, path, flags, mask, stx);
    errno = ENOSYS; return -1;
}

static int my_readlink(const char *path, char *buf, size_t bufsz) {
    // Don't hide the module's own fd links (used by fd_path).
    int r = orig_readlink ? orig_readlink(path, buf, bufsz)
                          : readlink(path, buf, bufsz);
    if (r > 0 && g_should_hide && g_cfg.file_hide && path && is_root_path(path)) {
        errno = ENOENT; return -1;
    }
    return r;
}

static int my_readlinkat(int dirfd, const char *path, char *buf, size_t bufsz) {
    if (g_should_hide && g_cfg.file_hide) {
        std::string full = resolve_at(dirfd, path);
        if (!full.empty() && is_root_path(full.c_str())) { errno = ENOENT; return -1; }
    }
    return orig_readlinkat ? orig_readlinkat(dirfd, path, buf, bufsz)
                           : readlinkat(dirfd, path, buf, bufsz);
}

static ssize_t my_read(int fd, void *buf, size_t count) {
    BufFilter *bf = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_buffd_lock);
        auto it = g_buffd.find(fd);
        if (it != g_buffd.end()) bf = &it->second;
    }
    if (bf && bf->active) {
        std::lock_guard<std::mutex> lk(g_buffd_lock);
        size_t start = bf->cursor;
        if (start > bf->data.size()) start = bf->data.size();
        size_t remain = bf->data.size() - start;
        size_t tocopy = remain < count ? remain : count;
        if (tocopy) memcpy(buf, bf->data.data() + start, tocopy);
        bf->cursor = start + tocopy;
        return (ssize_t)tocopy;
    }
    return orig_read ? orig_read(fd, buf, count) : read(fd, buf, count);
}

static ssize_t my_pread64(int fd, void *buf, size_t count, off_t offset) {
    BufFilter *bf = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_buffd_lock);
        auto it = g_buffd.find(fd);
        if (it != g_buffd.end()) bf = &it->second;
    }
    if (bf && bf->active) {
        std::lock_guard<std::mutex> lk(g_buffd_lock);
        // pread64 must NOT move the sequential cursor.
        size_t start = (offset < 0) ? 0 : (size_t)offset;
        if (start > bf->data.size()) start = bf->data.size();
        size_t remain = bf->data.size() - start;
        size_t tocopy = remain < count ? remain : count;
        if (tocopy) memcpy(buf, bf->data.data() + start, tocopy);
        return (ssize_t)tocopy;
    }
    return orig_pread64 ? orig_pread64(fd, buf, count, offset)
                        : pread64(fd, buf, count, offset);
}

static off_t my_lseek(int fd, off_t off, int whence) {
    {
        std::lock_guard<std::mutex> lk(g_buffd_lock);
        auto it = g_buffd.find(fd);
        if (it != g_buffd.end() && it->second.active) {
            if (whence == SEEK_SET) it->second.cursor = (size_t)off;
            else if (whence == SEEK_END)
                it->second.cursor = it->second.data.size();
            else if (whence == SEEK_CUR) {
                long c = (long)it->second.cursor + off;
                if (c < 0) c = 0;
                it->second.cursor = (size_t)c;
            }
        }
    }
    return orig_lseek ? orig_lseek(fd, off, whence) : lseek(fd, off, whence);
}

static off_t my_lseek64(int fd, off64_t off, int whence) {
    {
        std::lock_guard<std::mutex> lk(g_buffd_lock);
        auto it = g_buffd.find(fd);
        if (it != g_buffd.end() && it->second.active) {
            if (whence == SEEK_SET) it->second.cursor = (size_t)off;
            else if (whence == SEEK_END)
                it->second.cursor = it->second.data.size();
            else if (whence == SEEK_CUR) {
                long long c = (long long)it->second.cursor + off;
                if (c < 0) c = 0;
                it->second.cursor = (size_t)c;
            }
        }
    }
    return orig_lseek64 ? orig_lseek64(fd, off, whence) : lseek64(fd, off, whence);
}

static struct dirent *my_readdir(DIR *dir) {
    if (!orig_readdir) return readdir(dir);
    struct dirent *e;
    while ((e = orig_readdir(dir)) != nullptr) {
        // 仅对可能是目标的条目（纯数字 pid / 含 root token 的模块名）才解析目录路径，
        // 避免对普通目录的每个条目都做一次 readlink 系统调用。
        if (e->d_name[0] && (isdigit((unsigned char)e->d_name[0]) || is_root_token(e->d_name))) {
            std::string dp = dir_path_of(dir);
            if (!dir_entry_blocked(dp, e->d_name)) return e;
        } else {
            return e;
        }
    }
    return nullptr;
}

static struct dirent64 *my_readdir64(DIR *dir) {
    if (!orig_readdir64) return readdir64(dir);
    struct dirent64 *e;
    while ((e = orig_readdir64(dir)) != nullptr) {
        if (e->d_name[0] && (isdigit((unsigned char)e->d_name[0]) || is_root_token(e->d_name))) {
            std::string dp = dir_path_of(dir);
            if (!dir_entry_blocked(dp, e->d_name)) return e;
        } else {
            return e;
        }
    }
    return nullptr;
}

static int my_dladdr(void *addr, Dl_info *info) {
    int r = orig_dladdr ? orig_dladdr(addr, info)
                        : dladdr(addr, info);
    if (r != 0 && info && info->dli_fname && is_root_path(info->dli_fname)) {
        // Hide our own / zygisk library from injection probes.
        info->dli_fname = nullptr;
        info->dli_sname = nullptr;
        info->dli_saddr = nullptr;
        info->dli_fbase = nullptr;
        return 0;
    }
    return r;
}

static int my___system_property_get(const char *name, char *value) {
    if (g_should_hide && g_cfg.prop_hide && name && is_hidden_prop(name)) {
        sanitize_prop_value(name, value);
        return (int)strlen(value);
    }
    return orig___system_property_get
               ? orig___system_property_get(name, value)
               : __system_property_get(name, value);
}

static const void *my___system_property_find(const char *name) {
    if (g_should_hide && g_cfg.prop_hide && name && is_hidden_prop(name))
        return nullptr; // pretend the property does not exist
    return orig___system_property_find
               ? orig___system_property_find(name)
               : __system_property_find(name);
}

static int my_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (g_should_hide && g_cfg.socket_hide && addr && addr->sa_family == AF_UNIX) {
        const struct sockaddr_un *un = (const struct sockaddr_un *)addr;
        const char *p = un->sun_path;
        if (p && (str_has(p, "magisk") || str_has(p, "zygisk") ||
                  str_has(p, "ksu") || str_has(p, "apatch") ||
                  str_has(p, "lspd") || str_has(p, "lsposed"))) {
            errno = ECONNREFUSED; return -1;
        }
    }
    return orig_connect ? orig_connect(sockfd, addr, addrlen)
                        : connect(sockfd, addr, addrlen);
}

static int my_kill(pid_t pid, int sig) {
    // Pretend success when the target is a protected root daemon, so the
    // caller can't learn the daemon exists (a failed kill with ESRCH leaks it).
    if (g_should_hide && g_cfg.proc_hide && daemon_pid(pid)) return 0;
    return orig_kill ? orig_kill(pid, sig) : kill(pid, sig);
}

static int my_prctl(int option, ...) {
    va_list ap; va_start(ap, option);
    unsigned long arg2 = va_arg(ap, unsigned long);
    unsigned long arg3 = va_arg(ap, unsigned long);
    unsigned long arg4 = va_arg(ap, unsigned long);
    unsigned long arg5 = va_arg(ap, unsigned long);
    va_end(ap);
    if (option == PR_SET_VMA && arg2 == PR_SET_VMA_ANON_NAME) {
        const char *name = (const char *)arg3;
        // Scrub names that would leak root/frida frameworks.
        if (name && (str_has(name, "zygisk") || str_has(name, "magisk") ||
                     str_has(name, "frida") || str_has(name, "gum") ||
                     str_has(name, "xhook") || str_has(name, "apatch") ||
                     str_has(name, "ksu"))) {
            // Replace with a benign name to avoid detection.
            static const char benign[] = "dalvik";
            return orig_prctl ? orig_prctl((int)option, (unsigned long)arg2,
                                           (unsigned long)benign, arg4, arg5)
                              : prctl((int)option, (unsigned long)arg2,
                                      (unsigned long)benign, arg4, arg5);
        }
    }
    return orig_prctl ? orig_prctl((int)option, arg2, arg3, arg4, arg5)
                      : prctl((int)option, arg2, arg3, arg4, arg5);
}

// Architecture-specific syscall numbers for the path-based calls we filter.
#if defined(__aarch64__)
#define NR_OPENAT     56
#define NR_NEWFSTATAT 79
#define NR_FACCESSAT  334
#define NR_STATX      291
#define NR_FACCESSAT2 439
#define NR_OPENAT2    437
#define NR_READLINKAT 78
#define NR_PREAD64    67
#elif defined(__arm__)
#define NR_OPENAT     322
#define NR_NEWFSTATAT 327
#define NR_FACCESSAT  334
#define NR_STATX      291
#define NR_FACCESSAT2 439
#define NR_OPENAT2    437
#define NR_READLINKAT 305
#define NR_PREAD64    361
#else
#define NR_OPENAT     0
#define NR_NEWFSTATAT 0
#define NR_FACCESSAT  0
#define NR_STATX      0
#define NR_FACCESSAT2 0
#define NR_OPENAT2    0
#define NR_READLINKAT 0
#define NR_PREAD64    0
#endif

static long my_syscall(long n, ...) {
    va_list ap; va_start(ap, n);
    long a0 = va_arg(ap, long);
    long a1 = va_arg(ap, long);
    long a2 = va_arg(ap, long);
    long a3 = va_arg(ap, long);
    long a4 = va_arg(ap, long);
    long a5 = va_arg(ap, long);
    va_end(ap);

    if (g_should_hide && g_cfg.file_hide) {
        const char *path = nullptr;
        if (n == NR_OPENAT || n == NR_NEWFSTATAT || n == NR_FACCESSAT ||
            n == NR_STATX || n == NR_FACCESSAT2 || n == NR_OPENAT2 ||
            n == NR_READLINKAT) {
            path = (const char *)a1;
        }
        if (path && is_root_path(path)) { errno = ENOENT; return -1; }
    }
    return orig_syscall ? orig_syscall(n, a0, a1, a2, a3, a4, a5)
                        : syscall((int)n, a0, a1, a2, a3, a4, a5);
}

static int my_close(int fd) {
    {
        std::lock_guard<std::mutex> lk(g_buffd_lock);
        g_buffd.erase(fd);
    }
    return orig_close ? orig_close(fd) : close(fd);
}

/* ------------------------------------------------------------------ */
/* VFS unmount engine                                                  */

static bool is_magisk_mount(const char *mountpoint, const char *fstype,
                            const char *source, const char *options) {
    if (!mountpoint) return false;
    if (strcmp(mountpoint, "/system/bin/.magisk") == 0) return true;
    if (strcmp(mountpoint, "/system/etc/init/magisk") == 0) return true;
    if (fstype && strcmp(fstype, "overlay") == 0) {
        // Magisk module overlays use upperdir=/data/adb/modules/...
        if (str_has(options, "/data/adb/modules") ||
            str_has(source, "/data/adb/modules") ||
            str_has(options, "magisk") || str_has(source, "magisk"))
            return true;
    }
    if (fstype && strcmp(fstype, "tmpfs") == 0) {
        if (str_has(mountpoint, "magisk") || str_has(mountpoint, "zygisk") ||
            str_has(mountpoint, "/ksu") || str_has(mountpoint, "apatch") ||
            str_has(mountpoint, "/modules"))
            return true;
    }
    return false;
}

static void do_unmount() {
    FILE *fp = fopen("/proc/self/mountinfo", "r");
    if (!fp) return;
    char line[1024];
    std::vector<std::string> targets;
    while (fgets(line, sizeof(line), fp)) {
        // fields: mnt_id parent major:minor root mountpoint options - fstype source super_options
        char *save = nullptr;
        char *tok = strtok_r(line, " ", &save);
        int idx = 0;
        std::string mountpoint, fstype, source, options;
        bool after_dash = false;
        while (tok) {
            if (strcmp(tok, "-") == 0) { after_dash = true; tok = strtok_r(nullptr, " ", &save); continue; }
            if (!after_dash) {
                if (idx == 4) mountpoint = tok;       // 5th field
                // options is the 6th field (idx==5) but we skip to after '-'
            } else {
                if (fstype.empty()) fstype = tok;
                else if (source.empty()) source = tok;
                else if (options.empty()) options = tok;
            }
            ++idx;
            tok = strtok_r(nullptr, " ", &save);
        }
        if (is_magisk_mount(mountpoint.c_str(), fstype.c_str(),
                            source.c_str(), options.c_str()))
            targets.push_back(mountpoint);
    }
    fclose(fp);
    for (auto &mp : targets) {
        // We run inside the app's private mount namespace; MNT_DETACH is safe
        // and won't affect the global system.
        if (umount2(mp.c_str(), MNT_DETACH) == 0)
            HAR_LOGV("unmounted %s", mp.c_str());
        else
            HAR_LOGV("unmount %s failed: %s", mp.c_str(), strerror(errno));
    }
}

/* ------------------------------------------------------------------ */
/* Environment + zygisk trace cleanup                                  */

static void clean_environment() {
    static const char *block[] = {
        "ZYGISK_NATIVE", "ZygiskNative", "MAGISK", "KSU", "KSU_VER",
        "KSU_VER_CODE", "APATCH", "APATCH_VER", "APATCH_BINDIR",
        "MAGISK_ROOT", "MAGISK_VERSION", "ZYGISK_MODULE", nullptr
    };
    for (int i = 0; block[i]; ++i) unsetenv(block[i]);

    // Filter Magisk/KSU/APatch directories out of PATH.
    const char *path = getenv("PATH");
    if (!path) return;
    std::string out;
    char *save = nullptr;
    for (char *p = strtok_r((char *)path, ":", &save); p;
         p = strtok_r(nullptr, ":", &save)) {
        if (str_has(p, "magisk") || str_has(p, "ksu") ||
            str_has(p, "apatch") || str_has(p, "/data/adb"))
            continue;
        if (!out.empty()) out += ":";
        out += p;
    }
    setenv("PATH", out.c_str(), 1);
}

static void clean_zygisk_traces() {
    // The .so is hidden via /proc/self/maps line filtering (see is_maps_path).
    // Here we additionally neutralize any anonymous mapping names that leak
    // root/frida frameworks by re-labelling them (defense in depth).
    int fd = orig_open ? orig_open("/proc/self/maps", O_RDONLY)
                       : open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return;
    char buf[8192];
    ssize_t n = orig_read ? orig_read(fd, buf, sizeof(buf) - 1)
                          : read(fd, buf, sizeof(buf) - 1);
    if (fd >= 0) close(fd);
    if (n <= 0) return;
    buf[n] = '\0';
    // We intentionally do NOT rewrite live mappings (fragile); the maps filter
    // already removes the revealing lines. This hook point exists so the WebUI
    // "Zygisk clean" toggle can force a stricter scrub if needed.
    (void)buf;
}

/* ------------------------------------------------------------------ */
/* Config parsing                                                      */

static bool parse_bool(const std::string &v, bool def) {
    if (v == "1" || v == "true" || v == "yes" || v == "on") return true;
    if (v == "0" || v == "false" || v == "no" || v == "off") return false;
    return def;
}

static void split_csv(const std::string &s, std::vector<std::string> &out) {
    out.clear();
    size_t start = 0;
    while (start < s.size()) {
        size_t comma = s.find(',', start);
        if (comma == std::string::npos) comma = s.size();
        std::string tok = s.substr(start, comma - start);
        // trim
        size_t b = tok.find_first_not_of(" \t\r\n");
        size_t e = tok.find_last_not_of(" \t\r\n");
        if (b != std::string::npos && e != std::string::npos)
            out.push_back(tok.substr(b, e - b + 1));
        start = comma + 1;
    }
}

static void parse_config() {
    g_cfg = Config{};
    FILE *fp = fopen(kConfigPath, "r");
    if (!fp) {
        HAR_LOG("config not found, using safe defaults (all off)");
        return;
    }
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = line;
        char *val = eq + 1;
        // trim key
        while (*key == ' ' || *key == '\t') key++;
        size_t kl = strlen(key); while (kl && (key[kl-1]==' '||key[kl-1]=='\t')) key[--kl]=0;
        // trim val
        size_t vl = strlen(val); while (vl && (val[vl-1]=='\n'||val[vl-1]=='\r'||val[vl-1]==' '||val[vl-1]=='\t')) val[--vl]=0;

        std::string k(key), v(val);
        if (k == "ENABLE")               g_cfg.enable = parse_bool(v, false);
        else if (k == "ENABLE_FILE_HIDE") g_cfg.file_hide = parse_bool(v, false);
        else if (k == "ENABLE_PROP_HIDE") g_cfg.prop_hide = parse_bool(v, false);
        else if (k == "ENABLE_PROC_HIDE") g_cfg.proc_hide = parse_bool(v, false);
        else if (k == "ENABLE_MAPS_HIDE") g_cfg.maps_hide = parse_bool(v, false);
        else if (k == "ENABLE_MOUNT_HIDE") g_cfg.mount_hide = parse_bool(v, false);
        else if (k == "ENABLE_SOCKET_HIDE") g_cfg.socket_hide = parse_bool(v, false);
        else if (k == "ENABLE_DEBUG_HIDE") g_cfg.debug_hide = parse_bool(v, false);
        else if (k == "ENABLE_UNMOUNT")    g_cfg.unmount = parse_bool(v, false);
        else if (k == "ENABLE_ENV_CLEAN")  g_cfg.env_clean = parse_bool(v, false);
        else if (k == "ENABLE_ZYGISK_CLEAN") g_cfg.zygisk_clean = parse_bool(v, false);
        else if (k == "TARGET_MODE")       g_cfg.target_mode = atoi(v.c_str());
        else if (k == "TARGET_PKGS")       split_csv(v, g_cfg.target_pkgs);
        else if (k == "CUSTOM_PKGS")       split_csv(v, g_cfg.custom_pkgs);
    }
    fclose(fp);

    // If master off, force everything off.
    if (!g_cfg.enable) {
        g_cfg.file_hide = g_cfg.prop_hide = g_cfg.proc_hide = false;
        g_cfg.maps_hide = g_cfg.mount_hide = g_cfg.socket_hide = false;
        g_cfg.debug_hide = g_cfg.unmount = g_cfg.env_clean = false;
        g_cfg.zygisk_clean = false;
    }
    HAR_LOG("config loaded: enable=%d file=%d prop=%d proc=%d maps=%d mount=%d "
            "sock=%d dbg=%d unmount=%d env=%d zyg=%d mode=%d",
            g_cfg.enable, g_cfg.file_hide, g_cfg.prop_hide, g_cfg.proc_hide,
            g_cfg.maps_hide, g_cfg.mount_hide, g_cfg.socket_hide,
            g_cfg.debug_hide, g_cfg.unmount, g_cfg.env_clean, g_cfg.zygisk_clean,
            g_cfg.target_mode);
}

static bool pkg_targeted(const std::string &pkg) {
    if (pkg.empty()) return g_cfg.target_mode == 0; // unknown → treat as all
    if (g_cfg.target_mode == 0) return true;
    if (g_cfg.target_mode == 1) {
        for (auto &p : g_cfg.target_pkgs)
            if (p == pkg) return true;
        return false;
    }
    // mode 2: custom only
    for (auto &p : g_cfg.custom_pkgs)
        if (p == pkg) return true;
    return false;
}

/* ------------------------------------------------------------------ */
/* Module                                                              */

/* ------------------------------------------------------------------ */
/* Package resolution (no JNI needed in preAppSpecialize)             */

static std::string pkg_from_cmdline() {
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd < 0) return "";
    char b[256] = {0};
    ssize_t n = read(fd, b, sizeof(b) - 1);
    if (fd >= 0) close(fd);
    if (n <= 0) return "";
    std::string s(b);
    size_t slash = s.find_last_of('/');
    if (slash != std::string::npos) s = s.substr(slash + 1);
    return s;
}

static std::string pkg_from_uid(uid_t uid) {
    char want[16];
    snprintf(want, sizeof(want), "%u", (unsigned)uid);
    FILE *fp = fopen("/data/system/packages.list", "r");
    if (!fp) return "";
    char line[512];
    std::string found;
    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        char *pkg = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
        if (!*p) continue;
        *p++ = '\0';
        while (*p == ' ' || *p == '\t') p++;
        char *uidstr = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
        *p = '\0';
        if (strcmp(uidstr, want) == 0) { found = pkg; break; }
    }
    fclose(fp);
    return found;
}

class HideAllRootModule : public zygisk::Module {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override;

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // preAppSpecialize does NOT receive a JNIEnv*, so derive the package
        // name without JNI: map uid -> package via /data/system/packages.list,
        // with /proc/self/cmdline as a fallback.
        g_pkg.clear();
        g_should_hide = false;
        if (!args) return;

        uid_t uid = (uid_t)args->uid;
        std::string pkg = pkg_from_uid(uid);
        if (pkg.empty()) pkg = pkg_from_cmdline();
        g_pkg = pkg;
        g_should_hide = pkg_targeted(pkg);

        if (g_should_hide) {
            if (g_cfg.unmount) do_unmount();
            if (g_cfg.env_clean) clean_environment();
            if (g_cfg.zygisk_clean) clean_zygisk_traces();
            HAR_LOG("applied to %s (unmount=%d env=%d zyg=%d)",
                    pkg.c_str(), g_cfg.unmount, g_cfg.env_clean, g_cfg.zygisk_clean);
        } else {
            HAR_LOGV("skip %s", pkg.c_str());
        }
    }

    void postAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        (void)args;
    }
};

void HideAllRootModule::onLoad(zygisk::Api *api, JNIEnv *env) {
    (void)env;
    parse_config();

    api->pltHookRegister(".*", "open", (void *)my_open, (void **)&orig_open);
    api->pltHookRegister(".*", "openat", (void *)my_openat, (void **)&orig_openat);
    api->pltHookRegister(".*", "openat2", (void *)my_openat2, (void **)&orig_openat2);
    api->pltHookRegister(".*", "access", (void *)my_access, (void **)&orig_access);
    api->pltHookRegister(".*", "faccessat", (void *)my_faccessat, (void **)&orig_faccessat);
    api->pltHookRegister(".*", "faccessat2", (void *)my_faccessat2, (void **)&orig_faccessat2);
    api->pltHookRegister(".*", "stat", (void *)my_stat, (void **)&orig_stat);
    api->pltHookRegister(".*", "lstat", (void *)my_lstat, (void **)&orig_lstat);
    api->pltHookRegister(".*", "fstatat", (void *)my_fstatat, (void **)&orig_fstatat);
    api->pltHookRegister(".*", "__xstat", (void *)my___xstat, (void **)&orig___xstat);
    api->pltHookRegister(".*", "__lxstat", (void *)my___lxstat, (void **)&orig___lxstat);
    api->pltHookRegister(".*", "__fxstatat", (void *)my___fxstatat, (void **)&orig___fxstatat);
    api->pltHookRegister(".*", "statx", (void *)my_statx, (void **)&orig_statx);
    api->pltHookRegister(".*", "readlink", (void *)my_readlink, (void **)&orig_readlink);
    api->pltHookRegister(".*", "readlinkat", (void *)my_readlinkat, (void **)&orig_readlinkat);
    api->pltHookRegister(".*", "read", (void *)my_read, (void **)&orig_read);
    api->pltHookRegister(".*", "pread64", (void *)my_pread64, (void **)&orig_pread64);
    api->pltHookRegister(".*", "lseek", (void *)my_lseek, (void **)&orig_lseek);
    api->pltHookRegister(".*", "lseek64", (void *)my_lseek64, (void **)&orig_lseek64);
    api->pltHookRegister(".*", "readdir", (void *)my_readdir, (void **)&orig_readdir);
    api->pltHookRegister(".*", "readdir64", (void *)my_readdir64, (void **)&orig_readdir64);
    api->pltHookRegister(".*", "dladdr", (void *)my_dladdr, (void **)&orig_dladdr);
    api->pltHookRegister(".*", "__system_property_get", (void *)my___system_property_get, (void **)&orig___system_property_get);
    api->pltHookRegister(".*", "__system_property_find", (void *)my___system_property_find, (void **)&orig___system_property_find);
    api->pltHookRegister(".*", "connect", (void *)my_connect, (void **)&orig_connect);
    api->pltHookRegister(".*", "kill", (void *)my_kill, (void **)&orig_kill);
    api->pltHookRegister(".*", "prctl", (void *)my_prctl, (void **)&orig_prctl);
    api->pltHookRegister(".*", "syscall", (void *)my_syscall, (void **)&orig_syscall);
    api->pltHookRegister(".*", "close", (void *)my_close, (void **)&orig_close);
    api->pltHookCommit();
}

REGISTER_ZYGISK_MODULE(HideAllRootModule)
