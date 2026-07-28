/*
 * HideAllRoot — Zygisk native hide module (libzygisk-hide.so)
 * -----------------------------------------------------------
 * Intercepts the low-level syscalls / libc calls that root detectors
 * (Momo / Ruru / SpringRoot-春秋 / RootBeer / Play Integrity) rely on,
 * and feeds them sanitized results. All behaviour is driven by
 * /data/adb/hideallroot/config.conf so the operator can tune it from the
 * WebUI without recompiling.
 *
 * Hook categories (v1.2, comprehensive):
 *   1. File/access/stat   — hide su / magisk / ksu / apatch / lspd / busybox paths
 *   2. Property           — hide ro.magisk.* / ro.ksu.* / ro.apatch.* / ro.riru.* /
 *                           ro.lsposed.* and sanitize bootloader-unlock props
 *   3. Process enumeration— hide magiskd/zygiskd/lspd/ksud/apd from /proc
 *   4. Command execution  — block `su` / `magisk` / `ksu` / `apatch` from popen/execve
 *   5. Maps / memfd       — strip libzygisk / frida / xhook / memfd: zygisk_module_entry
 *   6. App list           — filter packages.xml / packages.list for root-manager pkgs
 *   7. Mount points       — strip magisk/ksu/apatch/zygisk overlay mount lines
 *   8. Daemon sockets     — strip magiskd/zygiskd sockets from /proc/net/unix
 *   9. Anti-debug         — zero TracerPid in /proc/self/status + block self ptrace
 *
 * Compatible: Magisk 25.0+ (native Zygisk). KernelSU / APatch require the
 * ZygiskNext companion module for this .so to load.
 *
 * Developer: MJH
 */

#include <zygisk.hpp>

#include <android/log.h>
#include <dlfcn.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cctype>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#define LOG_TAG "HideAllRoot"
#define HAR_LOG(...)  __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

/* ------------------------------------------------------------------ */
/* Runtime configuration (parsed from /data/adb/hideallroot/config.conf)*/
/* ------------------------------------------------------------------ */

static const char *kConfigPath = "/data/adb/hideallroot/config.conf";

struct Config {
    bool file_hide    = true;
    bool prop_hide    = true;
    bool native_hook  = true;
    bool applist_hide = true;
    bool proc_hide    = true;
    bool antidebug    = true;
    bool pi_fix       = true;
    bool mount_hide   = true;       // NEW v1.2: hide overlay/magisk mount lines
    bool dladdr_hide  = true;       // NEW v1.3: strip injection-lib paths from dladdr
    int  target_mode  = 0;          // 0=all 1=detect 2=custom
    std::vector<std::string> detect_pkgs;
    std::vector<std::string> custom_pkgs;
};

static Config g_cfg;
// Per-process decision: should we filter package lists for THIS process?
// (Excludes framework/system processes even when TARGET_MODE=all.)
static bool g_apply_applist = false;

/* Package names whose presence we hide from app-list / package scanners.
 * Covers Magisk (all forks), KernelSU, APatch, LSPosed, Riru, TaiChi,
 * EdXposed, SuperSU, Shamiko, Hide-My-Applist, BusyBox and the detectors
 * themselves. */
static const char *kHiddenPkgs[] = {
    // Magisk (official / Canary / Alpha / Kitsune)
    "com.topjohnwu.magisk",
    "com.topjohnwu.magisk.debug",
    "com.kitsune.magisk",
    "com.kitsune.magisk.debug",
    // KernelSU
    "me.weishu.kernelsu",
    "me.weishu.kernelsu.debug",
    "com.dergoogler.manager",
    "com.dergoogler.kernelsu.ui",
    // APatch
    "me.bmax.apatch",
    "me.bmax.apatch.debug",
    "com.apatch.manager",
    // LSPosed / Riru / TaiChi / EdXposed
    "org.lsposed.lspd",
    "org.lsposed.manager",
    "org.lsposed.android",
    "com.taichi.gen",
    "com.taichi.app",
    "com.elderdrivers.edxp",
    "com.elderdrivers.edxposed",
    // SuperSU / 旧版 root 管理
    "eu.chainfire.supersu",
    "com.noshufou.android.su",
    "com.koushikdutta.superuser",
    "com.topjohnwu.superuser",
    "com.kingroot.master",
    "com.kingo.root",
    "com.smedialink.kh",
    "com.joeykrim.rootbox",
    "com.ramdroid.appquarantine",
    // 隐藏类模块自身（防止被识别为"隐藏模块残留"）
    "com.tsng.hidemyapplist",   // Hide My Applist
    "me.weishu.shamiko",         // Shamiko
    "com.theringer.zygisknext",  // ZygiskNext（若有配套 App）
    // 检测工具本身（TARGET_MODE=1 时也会由 DETECT_PKGS 覆盖）
    "com.xtremelabs.momo",
    "com.springroot.ruru",
    "com.chunqiu.check",
    "com.softwinner.firetesting",
    "com.bunny.redtest",
    "com.kache.mroot",
    "com.wrbug.rootdetect",
    "com.joeykrim.rootcheck",
    "com.elvx.rootcheck",
    "bin.mt.plus",
    // 其它 root / 管理工具
    "com.termux", "ru.meefik.busybox", "com.magiskmanager",
    "com.omarea.vtools", "com.royal.busybox",
    nullptr,
};

static std::string trim(const std::string &s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a])) a++;
    while (b > a && std::isspace((unsigned char)s[b - 1])) b--;
    return s.substr(a, b - a);
}

static void split_csv(const std::string &s, std::vector<std::string> &out) {
    std::string cur;
    for (char c : s) {
        if (c == ',') { cur = trim(cur); if (!cur.empty()) out.push_back(cur); cur.clear(); }
        else cur += c;
    }
    cur = trim(cur);
    if (!cur.empty()) out.push_back(cur);
}

static bool parse_bool(const std::string &v) {
    return v == "1" || v == "true" || v == "yes" || v == "on";
}

static void load_config() {
    g_cfg = Config{};   // restore defaults
    FILE *f = fopen(kConfigPath, "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        std::string l = trim(line);
        if (l.empty() || l[0] == '#') continue;
        auto eq = l.find('=');
        if (eq == std::string::npos) continue;
        std::string key = trim(l.substr(0, eq));
        std::string val = trim(l.substr(eq + 1));
        if      (key == "ENABLE_FILE_HIDE")   g_cfg.file_hide   = parse_bool(val);
        else if (key == "ENABLE_PROP_HIDE")   g_cfg.prop_hide   = parse_bool(val);
        else if (key == "ENABLE_NATIVE_HOOK") g_cfg.native_hook = parse_bool(val);
        else if (key == "ENABLE_APPLIST_HIDE")g_cfg.applist_hide= parse_bool(val);
        else if (key == "ENABLE_PROC_HIDE")   g_cfg.proc_hide   = parse_bool(val);
        else if (key == "ENABLE_ANTIDEBUG")   g_cfg.antidebug   = parse_bool(val);
        else if (key == "ENABLE_PI_FIX")      g_cfg.pi_fix      = parse_bool(val);
        else if (key == "ENABLE_MOUNT_HIDE")  g_cfg.mount_hide  = parse_bool(val);
        else if (key == "ENABLE_DLADDR_HIDE") g_cfg.dladdr_hide = parse_bool(val);
        else if (key == "TARGET_MODE")        g_cfg.target_mode = atoi(val.c_str());
        else if (key == "DETECT_PKGS")        split_csv(val, g_cfg.detect_pkgs);
        else if (key == "CUSTOM_PKGS")        split_csv(val, g_cfg.custom_pkgs);
    }
    fclose(f);
}

/* ------------------------------------------------------------------ */
/* Block lists                                                         */
/* ------------------------------------------------------------------ */

static const char *kFilePathBlocks[] = {
    // su / superuser
    "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/dev/su",
    "/system/app/Superuser.apk", "/system/app/supersu",
    "/data/app/eu.chainfire.supersu",
    // magisk (官方 / Canary / Alpha / Kitsune)
    "/system/bin/magisk", "/system/xbin/magisk", "/sbin/magisk",
    "/data/adb/magisk", "/data/adb/magisk.db", "/data/adb/magisk.log",
    "/cache/magisk.log", "/cache/.magisk", "/dev/magisk", "/sbin/.magisk",
    "/data/adb/magisk.img", "magisk_merge",
    // magisk 模块目录（具体已知模块）
    "/data/adb/modules/lspd", "/data/adb/modules/riru",
    "/data/adb/modules/zygisk", "/data/adb/modules/zygisk-next",
    "/data/adb/modules/shamiko", "/data/adb/modules/hidemyapplist",
    "/data/adb/modules/zygisk_assistant", "/data/adb/modules/movecert",
    "/data/adb/modules/com.topjohnwu.magisk",
    "/data/app/com.topjohnwu.magisk",
    // KernelSU / APatch
    "/data/adb/ksu", "/data/adb/ap", "/data/adb/apatch",
    "/data/adb/modules/../ksu", "/data/adb/modules/../ap",
    // busybox
    "/system/xbin/busybox", "/sbin/busybox", "/magisk/.core/busybox",
    // zygisk 控制面
    "/dev/zygisk",
    // init / late_start 脚本
    "/data/adb/post-fs-data.d", "/data/adb/service.d",
    "/system/etc/init.d",
    // magiskinit / ramdisk / 其它残留
    "/debug_ramdisk", "/sbin/magiskinit", "/system/bin/magiskinit",
    "/metadata/magisk", "/data/adb/modules_update",
    "/system/lib64/libmagisk", "/system/lib/libmagisk",
    "/system/bin/ksud", "/system/bin/apd", "/system/bin/kernelsu",
    "/data/unencrypted/magisk", "/cache/magisk", "/dev/block/by-name/magisk",
    nullptr,
};

static bool path_blocked(const char *path) {
    if (!path) return false;
    for (auto p = kFilePathBlocks; *p; ++p)
        if (strstr(path, *p)) return true;
    return false;
}

/* Properties we must sanitize, and their clean factory values.
 * Includes root-framework props AND bootloader-unlock indicators that
 * Momo / SpringRoot flag. */
static bool prop_is_blocked(const char *name) {
    if (!name) return false;
    // root-framework prefix props
    if (!strncmp(name, "ro.magisk", 9) || !strncmp(name, "ro.zygisk", 9) ||
        !strncmp(name, "ro.ksu", 6) || !strncmp(name, "ro.apatch", 9) ||
        !strncmp(name, "ro.riru", 7) || !strncmp(name, "ro.lsposed", 10) ||
        !strncmp(name, "persist.magisk", 14) ||
        !strncmp(name, "persist.vendor.magisk", 20) ||
        !strncmp(name, "ro.daemon.magisk", 16) ||
        !strncmp(name, "ro.bin.magisk", 13))
        return true;
    static const char *exact[] = {
        "ro.debuggable", "ro.secure", "ro.build.type", "ro.build.tags",
        "ro.build.selinux", "init.svc.magiskd", "init.svc.zygiskd",
        "persist.sys.root", "ro.kernel.qemu", "ro.boot.vbmeta.device_state",
        // bootloader unlock 指示（Momo / SpringRoot 重点）
        "ro.boot.verifiedbootstate", "ro.boot.flash.locked",
        "ro.boot.veritymode", "ro.oem.lockstate",
        "ro.vendor.boot.verifiedbootstate", "ro.boot.warranty_bit",
        "ro.warranty_bit", "ro.boot.vbmeta.device_state",
        "ro.boot.ddr",
        nullptr,
    };
    for (auto p = exact; *p; ++p)
        if (!strcmp(name, *p)) return true;
    return false;
}

static const char *safe_prop_value(const char *name) {
    if (!strncmp(name, "ro.magisk", 9) || !strncmp(name, "ro.zygisk", 9) ||
        !strncmp(name, "ro.ksu", 6) || !strncmp(name, "ro.apatch", 9) ||
        !strncmp(name, "ro.riru", 7) || !strncmp(name, "ro.lsposed", 10) ||
        !strncmp(name, "persist.magisk", 14) ||
        !strncmp(name, "persist.vendor.magisk", 20) ||
        !strncmp(name, "ro.daemon.magisk", 16) ||
        !strncmp(name, "ro.bin.magisk", 13))
        return "";                       // 框架本身不存在
    if (!strcmp(name, "ro.debuggable"))      return "0";
    if (!strcmp(name, "ro.secure"))          return "1";
    if (!strcmp(name, "ro.build.type"))      return "user";
    if (!strcmp(name, "ro.build.tags"))      return "release-keys";
    if (!strcmp(name, "ro.build.selinux"))   return "enforcing";
    if (!strcmp(name, "init.svc.magiskd"))   return "";
    if (!strcmp(name, "init.svc.zygiskd"))   return "";
    if (!strcmp(name, "persist.sys.root"))   return "0";
    // bootloader 锁状态 -> 伪装为已锁
    if (!strcmp(name, "ro.boot.verifiedbootstate"))      return "green";
    if (!strcmp(name, "ro.vendor.boot.verifiedbootstate")) return "green";
    if (!strcmp(name, "ro.boot.vbmeta.device_state"))    return "locked";
    if (!strcmp(name, "ro.boot.flash.locked"))           return "1";
    if (!strcmp(name, "ro.boot.veritymode"))             return "enforcing";
    if (!strcmp(name, "ro.oem.lockstate"))               return "locked";
    if (!strcmp(name, "ro.boot.warranty_bit"))           return "0";
    if (!strcmp(name, "ro.warranty_bit"))                return "0";
    return "";
}

static const char *kProcNameBlocks[] = {
    "magisk", "magiskd", "zygisk", "zygiskd", "daemonsu", "supersu",
    "lspd", "lsposed", "edxp", "taichi", "ksud", "apd", "kernelsu", nullptr,
};

static bool proc_name_blocked(const char *comm) {
    if (!comm) return false;
    for (auto p = kProcNameBlocks; *p; ++p)
        if (strstr(comm, *p)) return true;
    return false;
}

static const char *kCmdBlocks[] = {
    "magisk", "zygisk", "supersu", "daemonsu", "ksu", "apatch",
    "/su", "kernelsu", nullptr,
};

static bool cmd_blocked(const char *s) {
    if (!s) return false;
    for (auto p = kCmdBlocks; *p; ++p)
        if (strstr(s, *p)) return true;
    return false;
}

/* ------------------------------------------------------------------ */
/* Original function pointers (filled by pltHookRegister)             */
/* ------------------------------------------------------------------ */

typedef int (*open_fn_t)(const char *, int, ...);
typedef int (*openat_fn_t)(int, const char *, int, ...);

static open_fn_t   orig_open      = nullptr;
static openat_fn_t orig_openat    = nullptr;
static int       (*orig_access)  (const char *, int)                              = nullptr;
static int       (*orig_faccessat)(int, const char *, int, int)                   = nullptr;
static int       (*orig_stat)    (const char *, struct stat *)                    = nullptr;
static int       (*orig_lstat)   (const char *, struct stat *)                    = nullptr;
static FILE     *(*orig_fopen)   (const char *, const char *)                     = nullptr;
static DIR      *(*orig_opendir) (const char *)                                   = nullptr;
static int       (*orig_readlink)(const char *, char *, size_t)                   = nullptr;
static char     *(*orig_realpath)(const char *, char *)                          = nullptr;
static int       (*orig_dladdr) (void *, Dl_info *)                              = nullptr;
static int       (*orig_sysprop_get)(const char *, char *)                        = nullptr;
static FILE     *(*orig_popen)   (const char *, const char *)                     = nullptr;
static int       (*orig_system) (const char *)                                    = nullptr;
static int       (*orig_execve) (const char *, char *const[], char *const[])      = nullptr;
static long      (*orig_ptrace) (int, ...)                                        = nullptr;
static ssize_t   (*orig_read)    (int, void *, size_t)                            = nullptr;
static ssize_t   (*orig_pread64) (int, void *, size_t, off64_t)                   = nullptr;
static int       (*orig_close)   (int)                                            = nullptr;

/* ------------------------------------------------------------------ */
/* Buffered content filter (for /proc maps, status, mounts, packages) */
/* ------------------------------------------------------------------ */

struct BufFilter {
    std::string data;
    size_t      off = 0;
    std::vector<std::string> block;
    bool        status_mode = false;   // true => rewrite TracerPid instead of drop lines
};

static std::unordered_map<int, BufFilter> g_buffds;
static std::mutex g_bufmtx;

static bool is_maps_path(const char *path) {
    if (!path) return false;
    size_t n = strlen(path);
    if (n < 5) return false;
    if (strcmp(path + n - 5, "/maps") != 0) return false;
    if (strncmp(path, "/proc/", 6) != 0) return false;
    return true;
}

static bool is_pkglist_path(const char *path) {
    if (!path) return false;
    return strstr(path, "/data/system/packages.xml") ||
           strstr(path, "/data/system/packages.list");
}

static bool is_status_path(const char *path) {
    if (!path) return false;
    if (!strcmp(path, "/proc/self/status")) return true;
    if (strncmp(path, "/proc/", 6) != 0) return false;
    const char *rest = path + 6;
    if (!isdigit((unsigned char)rest[0])) return false;
    const char *p = rest; while (isdigit((unsigned char)*p)) p++;
    return !strcmp(p, "/status");
}

static bool is_mounts_path(const char *path) {
    if (!path) return false;
    if (!strcmp(path, "/proc/mounts")) return true;
    if (!strcmp(path, "/proc/self/mountinfo")) return true;
    if (strncmp(path, "/proc/", 6) != 0) return false;
    const char *rest = path + 6;
    if (!isdigit((unsigned char)rest[0])) return false;
    const char *p = rest; while (isdigit((unsigned char)*p)) p++;
    return !strcmp(p, "/mountinfo") || !strcmp(p, "/mounts");
}

static bool is_netunix_path(const char *path) {
    return !strcmp(path, "/proc/net/unix") ||
           !strcmp(path, "/proc/net/tcp")  ||
           !strcmp(path, "/proc/net/tcp6");
}

static bool is_buildprop_path(const char *path) {
    if (!path) return false;
    size_t n = strlen(path);
    if (n >= 10 && !strcmp(path + n - 10, "build.prop")) {
        // 仅系统分区下的 build.prop，避免误伤应用私有文件
        return strstr(path, "/system") || strstr(path, "/vendor") ||
               strstr(path, "/product") || strstr(path, "/system_ext") ||
               strstr(path, "/odm");
    }
    if (n >= 11 && !strcmp(path + n - 11, "prop.default"))
        return true;
    return false;
}

static bool is_fdlink_path(const char *path) {
    if (!path) return false;
    if (strncmp(path, "/proc/self/fd/", 14) == 0) return true;
    if (strncmp(path, "/proc/", 6) != 0) return false;
    const char *rest = path + 6;
    if (!isdigit((unsigned char)rest[0])) return false;
    const char *p = rest; while (isdigit((unsigned char)*p)) p++;
    return !strncmp(p, "/fd/", 4);
}

/* 注入框架 / 隐藏模块相关的库路径特征（用于 dladdr / fd / 通用匹配）。 */
static bool injlib_blocked(const char *name) {
    if (!name) return false;
    static const char *sub[] = {
        "magisk", "zygisk", "frida", "lsplant", "xhook", "sandhook",
        "whale", "substrate", "inlinehook", "libwhale", "gum",
        "libnativebridge", "ksu", "apatch", "lspd", "riru",
        "libfrida", "frida-agent", "frida-gadget", "libDexHelper",
        "libepic", "dexmaker", "qbdi", "doom", "kernelsu", nullptr,
    };
    for (auto p = sub; *p; ++p)
        if (strstr(name, *p)) return true;
    return false;
}

/* Blocklists for the various virtual files. */
static std::vector<std::string> maps_blocklist() {
    return {
        "libzygisk", "zygisk", "Zygisk", "magisk", ".magisk",
        "/dev/zygisk", "/dev/magisk", "/data/adb/modules/hideallroot",
        // 注入框架 / 内存特征
        "frida", "libfrida", "frida-agent", "frida-gadget", "gum",
        "linjector", "xhook", "libDexHelper", "memfd:", "zygisk_module_entry",
        "lsplant", "sandhook", "libwhale", "whale", "substrate",
        "inlinehook", "libnativebridge", "libepic", "dexmaker", "qbdi", "doom",
        // 其它框架
        "lspd", "riru", "ksu", "apatch", "kernelsu",
    };
}

/* Lines to strip from /system/build.prop etc. (complements property hook). */
static std::vector<std::string> buildprop_blocklist() {
    return {
        "ro.build.tags=test-keys",
        "ro.debuggable=1",
        "ro.secure=0",
        "ro.build.type=userdebug",
        "ro.build.type=eng",
        "ro.build.flavor",
        "ro.build.characteristics=eng",
        "ro.boot.flash.locked=0",
        "ro.boot.verifiedbootstate=orange",
        "ro.boot.verifiedbootstate=yellow",
    };
}

static std::vector<std::string> applist_blocklist() {
    std::vector<std::string> blk;
    for (auto p = kHiddenPkgs; *p; ++p) blk.emplace_back(*p);
    for (auto &p : g_cfg.detect_pkgs) blk.push_back(p);
    for (auto &p : g_cfg.custom_pkgs) blk.push_back(p);
    return blk;
}

static std::vector<std::string> mounts_blocklist() {
    return {
        "magisk", "zygisk", "ksu", "apatch", "kernelsu", "lspd", "riru",
        "/data/adb/modules", "/dev/zygisk", "/dev/magisk",
        "modules.img", "magisk_merge",
    };
}

static std::vector<std::string> netunix_blocklist() {
    return { "magiskd", "zygiskd", "lspd", "ksud", "apd", "kernelsu" };
}

static std::string filter_lines(const std::string &in,
                                const std::vector<std::string> &block) {
    std::string out;
    size_t start = 0, pos;
    while ((pos = in.find('\n', start)) != std::string::npos) {
        std::string line = in.substr(start, pos - start);
        bool drop = false;
        for (auto &b : block)
            if (line.find(b) != std::string::npos) { drop = true; break; }
        if (!drop) { out += line; out += '\n'; }
        start = pos + 1;
    }
    if (start < in.size()) {
        std::string line = in.substr(start);
        bool drop = false;
        for (auto &b : block)
            if (line.find(b) != std::string::npos) { drop = true; break; }
        if (!drop) out += line;
    }
    return out;
}

/* Rewrite TracerPid to 0 so the process never looks debugged. */
static std::string filter_status(const std::string &in) {
    std::string out;
    size_t start = 0, pos;
    while ((pos = in.find('\n', start)) != std::string::npos) {
        std::string line = in.substr(start, pos - start);
        if (line.rfind("TracerPid:", 0) == 0) out += "TracerPid:\t0";
        else out += line;
        out += '\n';
        start = pos + 1;
    }
    if (start < in.size()) {
        std::string line = in.substr(start);
        if (line.rfind("TracerPid:", 0) == 0) out += "TracerPid:\t0";
        else out += line;
    }
    return out;
}

static void track_buffd(int fd, const std::vector<std::string> &block, bool status_mode = false) {
    if (fd < 0) return;
    std::string content;
    char buf[4096];
    ssize_t n;
    while ((n = orig_read(fd, buf, sizeof(buf))) > 0)
        content.append(buf, (size_t)n);
    BufFilter bf;
    bf.data = status_mode ? filter_status(content) : filter_lines(content, block);
    bf.off = 0;
    bf.block = block;
    bf.status_mode = status_mode;
    std::lock_guard<std::mutex> lk(g_bufmtx);
    g_buffds[fd] = std::move(bf);
}

static void drop_buffd(int fd) {
    std::lock_guard<std::mutex> lk(g_bufmtx);
    g_buffds.erase(fd);
}

/* ------------------------------------------------------------------ */
/* /proc/<pid> process-name peek (used to hide magisk/zygisk daemons)  */
/* ------------------------------------------------------------------ */

static bool proc_dir_or_file_blocked(const char *path, bool is_dir) {
    if (strncmp(path, "/proc/", 6) != 0) return false;
    const char *rest = path + 6;
    if (!strncmp(rest, "self/", 5)) return false;
    if (!strncmp(rest, "thread-self/", 12)) return false;
    if (!isdigit((unsigned char)rest[0])) return false;
    const char *p = rest;
    while (isdigit((unsigned char)*p)) p++;
    if (*p != '/') return false;          // not /proc/<pid>/something
    const char *file = p + 1;
    if (is_dir) {
        if (file[0] != '\0') return false; // only exact /proc/<pid>
    } else {
        bool want = !strcmp(file, "cmdline") || !strcmp(file, "comm") ||
                    !strcmp(file, "status")  || !strcmp(file, "stat") ||
                    !strcmp(file, "wchan")   || !strcmp(file, "exe");
        if (!want) return false;
    }
    long pid = atol(rest);
    char cpath[64];
    snprintf(cpath, sizeof(cpath), "/proc/%ld/comm", pid);
    int fd = orig_open(cpath, O_RDONLY);
    if (fd < 0) return false;
    char comm[64] = {0};
    ssize_t n = orig_read(fd, comm, sizeof(comm) - 1);
    orig_close(fd);
    if (n <= 0) return false;
    if (comm[n - 1] == '\n') comm[n - 1] = 0;
    return proc_name_blocked(comm);
}

/* ------------------------------------------------------------------ */
/* Process-name resolution for targeting                              */
/* ------------------------------------------------------------------ */

static std::string get_self_package() {
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd < 0) return "";
    char buf[256] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return "";
    return std::string(buf);
}

static bool is_target_pkg(const std::string &pkg) {
    if (g_cfg.target_mode == 0) return true;   // all
    if (g_cfg.target_mode == 1) {
        for (auto &p : g_cfg.detect_pkgs)
            if (p == pkg) return true;
        return false;
    }
    for (auto &p : g_cfg.custom_pkgs)
        if (p == pkg) return true;
    return false;
}

static bool should_applist_filter(const std::string &pkg) {
    if (!g_cfg.applist_hide) return false;
    static const char *kSys[] = {
        "system_server", "android", "zygote", "zygote64",
        "surfaceflinger", "adbd", "logd", nullptr,
    };
    for (auto s = kSys; *s; ++s)
        if (pkg == *s) return false;
    if (g_cfg.target_mode == 0) return true;
    return is_target_pkg(pkg);
}

/* ------------------------------------------------------------------ */
/* Hook implementations                                               */
/* ------------------------------------------------------------------ */

static int my_open(const char *path, int flags, ...) {
    va_list ap; va_start(ap, flags);
    int mode = va_arg(ap, int);
    va_end(ap);

    if (path) {
        if (g_cfg.file_hide && path_blocked(path)) { errno = ENOENT; return -1; }
        if (g_cfg.proc_hide && proc_dir_or_file_blocked(path, false)) { errno = ENOENT; return -1; }

        // 调试器检测：TracerPid 归零
        if (g_cfg.antidebug && is_status_path(path)) {
            int fd = orig_open(path, flags, mode);
            if (fd >= 0) track_buffd(fd, {}, true);
            return fd;
        }
        // 挂载点异常：剔除 magisk/ksu/apatch/zygisk 挂载行
        if (g_cfg.mount_hide && is_mounts_path(path)) {
            int fd = orig_open(path, flags, mode);
            if (fd >= 0) track_buffd(fd, mounts_blocklist());
            return fd;
        }
        // 守护进程 socket：剔除 magiskd/zygiskd 等
        if (g_cfg.proc_hide && is_netunix_path(path)) {
            int fd = orig_open(path, flags, mode);
            if (fd >= 0) track_buffd(fd, netunix_blocklist());
            return fd;
        }
        // build.prop 行级过滤（与属性 Hook 互补）
        if (g_cfg.file_hide && is_buildprop_path(path)) {
            int fd = orig_open(path, flags, mode);
            if (fd >= 0) track_buffd(fd, buildprop_blocklist());
            return fd;
        }
        // 内存映射：剔除 zygisk/frida/xhook/memfd 等特征行
        if (is_maps_path(path)) {
            int fd = orig_open(path, flags, mode);
            if (fd >= 0) track_buffd(fd, maps_blocklist());
            return fd;
        }
        // 应用列表：过滤 root 管理包名
        if (g_apply_applist && is_pkglist_path(path)) {
            int fd = orig_open(path, flags, mode);
            if (fd >= 0) track_buffd(fd, applist_blocklist());
            return fd;
        }
    }
    return orig_open(path, flags, mode);
}

static int my_openat(int dirfd, const char *path, int flags, ...) {
    va_list ap; va_start(ap, flags);
    int mode = va_arg(ap, int);
    va_end(ap);

    if (path) {
        if (g_cfg.file_hide && path_blocked(path)) { errno = ENOENT; return -1; }
        if (g_cfg.proc_hide && proc_dir_or_file_blocked(path, false)) { errno = ENOENT; return -1; }

        if (g_cfg.antidebug && is_status_path(path)) {
            int fd = orig_openat(dirfd, path, flags, mode);
            if (fd >= 0) track_buffd(fd, {}, true);
            return fd;
        }
        if (g_cfg.mount_hide && is_mounts_path(path)) {
            int fd = orig_openat(dirfd, path, flags, mode);
            if (fd >= 0) track_buffd(fd, mounts_blocklist());
            return fd;
        }
        if (g_cfg.proc_hide && is_netunix_path(path)) {
            int fd = orig_openat(dirfd, path, flags, mode);
            if (fd >= 0) track_buffd(fd, netunix_blocklist());
            return fd;
        }
        if (g_cfg.file_hide && is_buildprop_path(path)) {
            int fd = orig_openat(dirfd, path, flags, mode);
            if (fd >= 0) track_buffd(fd, buildprop_blocklist());
            return fd;
        }
        if (is_maps_path(path)) {
            int fd = orig_openat(dirfd, path, flags, mode);
            if (fd >= 0) track_buffd(fd, maps_blocklist());
            return fd;
        }
        if (g_apply_applist && is_pkglist_path(path)) {
            int fd = orig_openat(dirfd, path, flags, mode);
            if (fd >= 0) track_buffd(fd, applist_blocklist());
            return fd;
        }
    }
    return orig_openat(dirfd, path, flags, mode);
}

static int my_access(const char *path, int mode) {
    if (path && g_cfg.file_hide && path_blocked(path)) { errno = ENOENT; return -1; }
    if (path && g_cfg.proc_hide && proc_dir_or_file_blocked(path, false)) { errno = ENOENT; return -1; }
    return orig_access(path, mode);
}

static int my_faccessat(int dirfd, const char *path, int mode, int flags) {
    if (path && g_cfg.file_hide && path_blocked(path)) { errno = ENOENT; return -1; }
    if (path && g_cfg.proc_hide && proc_dir_or_file_blocked(path, false)) { errno = ENOENT; return -1; }
    return orig_faccessat(dirfd, path, mode, flags);
}

static int my_stat(const char *path, struct stat *buf) {
    if (path && g_cfg.file_hide && path_blocked(path)) { errno = ENOENT; return -1; }
    if (path && g_cfg.proc_hide && proc_dir_or_file_blocked(path, false)) { errno = ENOENT; return -1; }
    return orig_stat(path, buf);
}

static int my_lstat(const char *path, struct stat *buf) {
    if (path && g_cfg.file_hide && path_blocked(path)) { errno = ENOENT; return -1; }
    if (path && g_cfg.proc_hide && proc_dir_or_file_blocked(path, false)) { errno = ENOENT; return -1; }
    return orig_lstat(path, buf);
}

static FILE *my_fopen(const char *path, const char *mode) {
    if (path) {
        if (g_cfg.file_hide && path_blocked(path)) { errno = ENOENT; return nullptr; }
        if (g_cfg.proc_hide && proc_dir_or_file_blocked(path, false)) { errno = ENOENT; return nullptr; }

        if (g_cfg.antidebug && is_status_path(path)) {
            FILE *f = orig_fopen(path, mode);
            if (f) track_buffd(fileno(f), {}, true);
            return f;
        }
        if (g_cfg.mount_hide && is_mounts_path(path)) {
            FILE *f = orig_fopen(path, mode);
            if (f) track_buffd(fileno(f), mounts_blocklist());
            return f;
        }
        if (g_cfg.proc_hide && is_netunix_path(path)) {
            FILE *f = orig_fopen(path, mode);
            if (f) track_buffd(fileno(f), netunix_blocklist());
            return f;
        }
        if (g_cfg.file_hide && is_buildprop_path(path)) {
            FILE *f = orig_fopen(path, mode);
            if (f) track_buffd(fileno(f), buildprop_blocklist());
            return f;
        }
        if (is_maps_path(path)) {
            FILE *f = orig_fopen(path, mode);
            if (f) track_buffd(fileno(f), maps_blocklist());
            return f;
        }
        if (g_apply_applist && is_pkglist_path(path)) {
            FILE *f = orig_fopen(path, mode);
            if (f) track_buffd(fileno(f), applist_blocklist());
            return f;
        }
    }
    return orig_fopen(path, mode);
}

static DIR *my_opendir(const char *name) {
    if (name && g_cfg.proc_hide && proc_dir_or_file_blocked(name, true)) {
        errno = ENOENT; return nullptr;
    }
    return orig_opendir(name);
}

static int my_readlink(const char *path, char *buf, size_t bufsiz) {
    if (path && g_cfg.file_hide && path_blocked(path)) { errno = ENOENT; return -1; }
    if (path && g_cfg.proc_hide && is_fdlink_path(path)) {
        // 解析 /proc/self/fd/N 真实目标，命中隐藏特征则伪装为失效链接
        char tmp[4096];
        ssize_t n = orig_readlink(path, tmp, sizeof(tmp) - 1);
        if (n > 0) {
            tmp[n] = '\0';
            if (injlib_blocked(tmp) || path_blocked(tmp)) { errno = ENOENT; return -1; }
            return orig_readlink(path, buf, bufsiz);
        }
        return n;
    }
    return orig_readlink(path, buf, bufsiz);
}

static char *my_realpath(const char *path, char *resolved) {
    if (path && g_cfg.file_hide && path_blocked(path)) { errno = ENOENT; return nullptr; }
    return orig_realpath(path, resolved);
}

/* Strip injection-library paths from dladdr() results.
 * Momo / Ruru call dladdr() on function pointers to discover injected
 * libraries (magisk / zygisk / frida / lsplant / xhook ...). */
static int my_dladdr(void *addr, Dl_info *info) {
    int r = orig_dladdr(addr, info);
    if (r && info && g_cfg.dladdr_hide && info->dli_fname && injlib_blocked(info->dli_fname)) {
        info->dli_fname = "";
        info->dli_sname = "";
    }
    return r;
}

static int my_sysprop_get(const char *name, char *value) {
    if (name && g_cfg.prop_hide && prop_is_blocked(name)) {
        const char *safe = safe_prop_value(name);
        if (value) {
            size_t len = strlen(safe);
            if (len >= 92) len = 91;
            memcpy(value, safe, len);
            value[len] = '\0';
        }
        return (int)strlen(safe);
    }
    return orig_sysprop_get(name, value);
}

static FILE *my_popen(const char *command, const char *type) {
    if (command && cmd_blocked(command)) { errno = ENOENT; return nullptr; }
    return orig_popen(command, type);
}

static int my_system(const char *command) {
    if (command && cmd_blocked(command)) { errno = ENOENT; return -1; }
    return orig_system(command);
}

static int my_execve(const char *path, char *const argv[], char *const envp[]) {
    if (path && cmd_blocked(path)) { errno = ENOENT; return -1; }
    if (argv && argv[0] && cmd_blocked(argv[0])) { errno = ENOENT; return -1; }
    return orig_execve(path, argv, envp);
}

static long my_ptrace(int request, ...) {
    va_list ap; va_start(ap, request);
    pid_t pid = va_arg(ap, pid_t);
    void *addr = va_arg(ap, void *);
    void *data = va_arg(ap, void *);
    va_end(ap);
    if (g_cfg.antidebug &&
        (request == PTRACE_ATTACH || request == PTRACE_SEIZE)) {
        // Block a process from attaching to itself (Ruru's hook-trap technique).
        if (pid == 0 || pid == getpid()) { errno = EPERM; return -1; }
    }
    return orig_ptrace(request, pid, addr, data);
}

static ssize_t my_read(int fd, void *buf, size_t count) {
    {
        std::lock_guard<std::mutex> lk(g_bufmtx);
        auto it = g_buffds.find(fd);
        if (it != g_buffds.end()) {
            BufFilter &bf = it->second;
            size_t remain = bf.data.size() - bf.off;
            size_t tocopy = remain < count ? remain : count;
            if (tocopy) memcpy(buf, bf.data.data() + bf.off, tocopy);
            bf.off += tocopy;
            return (ssize_t)tocopy;
        }
    }
    return orig_read(fd, buf, count);
}

static ssize_t my_pread64(int fd, void *buf, size_t count, off64_t offset) {
    {
        std::lock_guard<std::mutex> lk(g_bufmtx);
        auto it = g_buffds.find(fd);
        if (it != g_buffds.end()) {
            BufFilter &bf = it->second;
            size_t remain = bf.data.size() - bf.off;
            size_t tocopy = remain < count ? remain : count;
            if (tocopy) memcpy(buf, bf.data.data() + bf.off, tocopy);
            bf.off += tocopy;
            return (ssize_t)tocopy;
        }
    }
    return orig_pread64(fd, buf, count, offset);
}

static int my_close(int fd) {
    if (fd >= 0) drop_buffd(fd);
    return orig_close(fd);
}

/* ------------------------------------------------------------------ */
/* Module entry                                                        */
/* ------------------------------------------------------------------ */

class HideModule : public zygisk::Module {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        (void)api; (void)env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        (void)args;
        load_config();
        std::string pkg = get_self_package();

        if (!g_cfg.native_hook) return;
        if (!is_target_pkg(pkg)) return;   // do not touch non-target processes

        bool applist = should_applist_filter(pkg);
        g_apply_applist = applist;   // used by my_open/my_openat/my_fopen

        zygisk::Api *api = this->api;

        #define REG(repl, orig, sym) \
            api->pltHookRegister(".*", sym, (void *)repl, (void **)&orig)

        if (g_cfg.file_hide || g_cfg.proc_hide || applist) {
            REG(my_open,       orig_open,       "open");
            REG(my_openat,     orig_openat,     "openat");
            REG(my_access,     orig_access,     "access");
            REG(my_faccessat,  orig_faccessat,  "faccessat");
            REG(my_stat,       orig_stat,       "stat");
            REG(my_lstat,      orig_lstat,      "lstat");
            REG(my_fopen,      orig_fopen,      "fopen");
            REG(my_readlink,   orig_readlink,   "readlink");
            REG(my_realpath,   orig_realpath,   "realpath");
        }
        if (g_cfg.proc_hide) {
            REG(my_opendir, orig_opendir, "opendir");
        }
        if (g_cfg.dladdr_hide) {
            REG(my_dladdr, orig_dladdr, "dladdr");
        }
        if (g_cfg.prop_hide) {
            REG(my_sysprop_get, orig_sysprop_get, "__system_property_get");
        }
        // 内容级过滤（maps / status / mounts / netunix / packages.xml）需要 read + close
        if (g_cfg.file_hide || applist || g_cfg.mount_hide ||
            g_cfg.antidebug || g_cfg.proc_hide) {
            REG(my_read,    orig_read,    "read");
            REG(my_pread64, orig_pread64, "pread64");
            REG(my_close,   orig_close,   "close");
        }
        if (g_cfg.file_hide) {
            REG(my_popen,  orig_popen,  "popen");
            REG(my_system, orig_system, "system");
            REG(my_execve, orig_execve, "execve");
        }
        if (g_cfg.antidebug) {
            REG(my_ptrace, orig_ptrace, "ptrace");
        }

        #undef REG

        if (!api->pltHookCommit())
            HAR_LOG("pltHookCommit failed for %s", pkg.c_str());
        else
            HAR_LOG("hooks active for %s (file=%d prop=%d proc=%d applist=%d mount=%d adb=%d)",
                    pkg.c_str(), g_cfg.file_hide, g_cfg.prop_hide,
                    g_cfg.proc_hide, applist, g_cfg.mount_hide, g_cfg.antidebug);
    }
};

REGISTER_ZYGISK_MODULE(HideModule)
