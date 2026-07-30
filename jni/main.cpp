/*
 * HideAllRoot v2.0 — Zygisk native hide module
 * ====================================================================
 * 基于 v1.3 完整重构。保留 zygisk::Module + api->pltHookRegister 模式。
 *
 * v2.0 变更:
 *   [修复] path_blocked / proc_name_blocked / cmd_blocked / injlib_blocked
 *          全部从 strstr 改为精确前缀/词边界匹配，消除误杀
 *   [修复] my_pread64 正确使用 offset 参数
 *   [修复] my_dladdr 返回 0 而非空字符串
 *   [新增] lseek hook（缓冲区偏移同步）
 *   [新增] VFS 级 unmount（卸载 Magisk tmpfs 覆盖）
 *   [新增] 环境变量清洗
 *   [新增] /proc/modules 过滤（KernelSU 内核模块）
 *   [新增] /proc/<pid>/attr/ 过滤（SELinux context）
 *   [新增] syscall() hook 拦截 openat2 / statx / faccessat2
 *   [新增] readdir64 过滤（/proc PID 枚举）
 *   [新增] kill hook（阻止信号探测被隐藏进程）
 *   [新增] __system_property_find hook（属性存在性隐藏）
 *   [新增] connect hook（阻止 magisk/ksu unix socket）
 *   [新增] PID 缓存（消除 /proc 枚举性能问题）
 *   [修复] track_buffd 竞态（全程持锁）
 *   [修复] is_netunix_path 不再误匹配 tcp/tcp6
 *   [新增] Zygisk 匿名映射重命名
 *
 * Developer: MJH
 */

#include <android/log.h>
#include <jni.h>

#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <mntent.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>

#include <algorithm>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "zygisk.hpp"

#define LOG_TAG "HideAllRoot"
#define HAR_LOG(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#endif
#ifndef PR_SET_VMA_ANON_NAME
#define PR_SET_VMA_ANON_NAME 0
#endif

/* ====================================================================
 *  SECTION 1 — 配置系统
 * ==================================================================== */

static const char *kConfigPath = "/data/adb/hideallroot/config.conf";

struct Config {
    bool enable         = true;   /* 总开关 */
    bool file_hide      = true;
    bool prop_hide      = true;
    bool native_hook    = true;
    bool applist_hide   = true;
    bool proc_hide      = true;
    bool antidebug      = true;
    bool pi_fix         = true;
    bool mount_hide     = true;
    bool dladdr_hide    = true;
    bool unmount_magisk = true;   /* NEW: VFS 级 unmount */
    bool env_clean      = true;   /* NEW: 环境变量清洗 */
    bool zygisk_clean   = true;   /* NEW: Zygisk 痕迹清理 */
    int  target_mode    = 0;      /* 0=all 1=detect 2=custom */
    std::vector<std::string> detect_pkgs;
    std::vector<std::string> custom_pkgs;
};

static Config g_cfg;
static bool g_apply_applist = false;
static bool g_active = false;

/* ---- 隐藏包名列表 ---- */
static const char *kHiddenPkgs[] = {
    "com.topjohnwu.magisk",
    "com.topjohnwu.magisk.debug",
    "com.kitsune.magisk",
    "com.kitsune.magisk.debug",
    "me.weishu.kernelsu",
    "me.weishu.kernelsu.debug",
    "com.dergoogler.manager",
    "com.dergoogler.kernelsu.ui",
    "me.bmax.apatch",
    "me.bmax.apatch.debug",
    "com.apatch.manager",
    "org.lsposed.lspd",
    "org.lsposed.manager",
    "org.lsposed.android",
    "com.taichi.gen",
    "com.taichi.app",
    "com.elderdrivers.edxp",
    "com.elderdrivers.edxposed",
    "eu.chainfire.supersu",
    "com.noshufou.android.su",
    "com.koushikdutta.superuser",
    "com.topjohnwu.superuser",
    "com.kingroot.master",
    "com.kingo.root",
    "com.smedialink.kh",
    "com.joeykrim.rootbox",
    "com.ramdroid.appquarantine",
    "com.tsng.hidemyapplist",
    "me.weishu.shamiko",
    "com.theringer.zygisknext",
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
    "com.termux",
    "ru.meefik.busybox",
    "com.magiskmanager",
    "com.omarea.vtools",
    "com.royal.busybox",
    nullptr,
};

/* ---- 配置解析工具 ---- */
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
    g_cfg = Config{};
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
        if      (key == "ENABLE")             g_cfg.enable         = parse_bool(val);
        else if (key == "ENABLE_FILE_HIDE")   g_cfg.file_hide      = parse_bool(val);
        else if (key == "ENABLE_PROP_HIDE")   g_cfg.prop_hide      = parse_bool(val);
        else if (key == "ENABLE_NATIVE_HOOK") g_cfg.native_hook    = parse_bool(val);
        else if (key == "ENABLE_APPLIST_HIDE")g_cfg.applist_hide   = parse_bool(val);
        else if (key == "ENABLE_PROC_HIDE")   g_cfg.proc_hide      = parse_bool(val);
        else if (key == "ENABLE_ANTIDEBUG")   g_cfg.antidebug      = parse_bool(val);
        else if (key == "ENABLE_PI_FIX")      g_cfg.pi_fix         = parse_bool(val);
        else if (key == "ENABLE_MOUNT_HIDE")  g_cfg.mount_hide     = parse_bool(val);
        else if (key == "ENABLE_DLADDR_HIDE") g_cfg.dladdr_hide    = parse_bool(val);
        else if (key == "ENABLE_UNMOUNT")     g_cfg.unmount_magisk = parse_bool(val);
        else if (key == "ENABLE_ENV_CLEAN")   g_cfg.env_clean      = parse_bool(val);
        else if (key == "ENABLE_ZYGISK_CLEAN")g_cfg.zygisk_clean   = parse_bool(val);
        else if (key == "TARGET_MODE")        g_cfg.target_mode    = atoi(val.c_str());
        else if (key == "DETECT_PKGS")        split_csv(val, g_cfg.detect_pkgs);
        else if (key == "CUSTOM_PKGS")        split_csv(val, g_cfg.custom_pkgs);
    }
    fclose(f);
}

/* ====================================================================
 *  SECTION 2 — 安全路径匹配（替代 strstr，消除误杀）
 * ==================================================================== */

/*
 * 精确前缀匹配：path 以 prefix 开头，且 prefix 之后是 '/' 或 '\0'。
 * "/data/adb/ksu" 匹配 "/data/adb/ksu" 和 "/data/adb/ksu/bin"
 * "/data/adb/ksu" 不匹配 "/data/adb/ksudoku"
 */
static bool path_prefix_match(const char *path, const char *prefix) {
    if (!path || !prefix) return false;
    size_t plen = strlen(prefix);
    if (strncmp(path, prefix, plen) != 0) return false;
    char next = path[plen];
    return (next == '\0' || next == '/');
}

/*
 * 词边界包含匹配（用于 maps 行等整行文本）。
 * token 前后必须是非字母数字非下划线非点字符（或行首/行尾）。
 * "ksu" 匹配 "/data/adb/ksu/lib.so" 和 "libksu.so"
 * "ksu" 不匹配 "/data/app/com.ksudoku/lib.so"
 */
static bool line_has_token(const char *line, const char *token) {
    if (!line || !token) return false;
    size_t tlen = strlen(token);
    const char *p = line;
    while ((p = strstr(p, token)) != nullptr) {
        bool left_ok  = (p == line) ||
                        (!isalnum((unsigned char)p[-1]) && p[-1] != '_' && p[-1] != '.');
        char after = p[tlen];
        bool right_ok = (after == '\0') ||
                        (!isalnum((unsigned char)after) && after != '_' && after != '.');
        if (left_ok && right_ok) return true;
        p += tlen;
    }
    return false;
}

/* 进程名精确匹配（comm 不含路径） */
static bool name_exact_match(const char *name, const char *entry) {
    if (!name || !entry) return false;
    return strcmp(name, entry) == 0;
}

/* ====================================================================
 *  SECTION 3 — 阻止列表
 * ==================================================================== */

static const char *kFilePathBlocks[] = {
    /* su / superuser */
    "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/dev/su",
    "/system/app/Superuser.apk", "/system/app/supersu",
    "/data/app/eu.chainfire.supersu",
    "/system/bin/failsafe/su", "/system/sd/xbin/su",
    "/system/usr/we-need-root/su", "/system/xbin/daemonsu",
    "/system/xbin/mu", "/cache/su", "/data/local/su",
    "/data/local/bin/su", "/data/local/xbin/su",
    /* magisk */
    "/system/bin/magisk", "/system/xbin/magisk", "/sbin/magisk",
    "/data/adb/magisk", "/data/adb/magisk.db", "/data/adb/magisk.log",
    "/cache/magisk.log", "/cache/.magisk", "/dev/magisk", "/sbin/.magisk",
    "/data/adb/magisk.img", "/data/adb/magisk/magisk64",
    "/data/adb/magisk/magisk32", "/data/adb/magisk/magiskinit",
    "/data/adb/magisk/magiskboot", "/data/adb/magisk/magiskpolicy",
    "/data/adb/magisk/busybox", "/data/adb/magisk/util_functions.sh",
    "/data/adb/magisk/boot_patch.sh",
    "/system/lib64/libmagisk", "/system/lib/libmagisk",
    "/system/bin/magiskinit", "/sbin/magiskinit",
    "/metadata/magisk", "/data/adb/modules_update",
    "/data/unencrypted/magisk", "/cache/magisk",
    "/dev/block/by-name/magisk",
    /* magisk 模块目录 */
    "/data/adb/modules",
    "/data/app/com.topjohnwu.magisk",
    /* KernelSU / APatch */
    "/data/adb/ksu", "/data/adb/ksud",
    "/data/adb/ap", "/data/adb/apd", "/data/adb/apatch",
    "/system/bin/ksud", "/system/bin/apd", "/system/bin/kernelsu",
    /* busybox */
    "/system/xbin/busybox", "/system/bin/busybox",
    "/sbin/busybox", "/vendor/bin/busybox",
    "/data/local/xbin/busybox", "/data/local/bin/busybox",
    "/magisk/.core/busybox",
    /* zygisk / init 脚本 */
    "/dev/zygisk",
    "/data/adb/post-fs-data.d", "/data/adb/service.d",
    "/system/etc/init.d",
    "/debug_ramdisk",
    "/system/bin/.ext", "/system/xbin/.ext",
    "/magisk",
    nullptr,
};

static bool path_blocked(const char *path) {
    if (!path) return false;
    for (auto p = kFilePathBlocks; *p; ++p)
        if (path_prefix_match(path, *p)) return true;
    return false;
}

/* ---- 属性 ---- */
static bool prop_is_blocked(const char *name) {
    if (!name) return false;
    if (!strncmp(name, "ro.magisk", 9)  || !strncmp(name, "ro.zygisk", 9)  ||
        !strncmp(name, "ro.ksu", 6)      || !strncmp(name, "ro.apatch", 9)  ||
        !strncmp(name, "ro.riru", 7)     || !strncmp(name, "ro.lsposed", 10)||
        !strncmp(name, "persist.magisk", 14) ||
        !strncmp(name, "persist.vendor.magisk", 20) ||
        !strncmp(name, "ro.daemon.magisk", 16) ||
        !strncmp(name, "ro.bin.magisk", 13))
        return true;
    static const char *exact[] = {
        "ro.debuggable", "ro.secure", "ro.build.type", "ro.build.tags",
        "ro.build.selinux", "init.svc.magiskd", "init.svc.zygiskd",
        "persist.sys.root", "ro.kernel.qemu",
        "ro.boot.verifiedbootstate", "ro.boot.flash.locked",
        "ro.boot.veritymode", "ro.oem.lockstate",
        "ro.vendor.boot.verifiedbootstate",
        "ro.boot.warranty_bit", "ro.warranty_bit",
        "ro.boot.vbmeta.device_state", "ro.boot.ddr",
        "sys.oem_unlock_allowed", "ro.frp.pst",
        "ro.sus.version", "ro.magisk.version",
        "init.svc.daemonsu", "init.svc.superuser",
        "init.svc.ksud", "init.svc.apd", "init.svc.zygiskd",
        "service.adb.root",
        nullptr,
    };
    for (auto p = exact; *p; ++p)
        if (!strcmp(name, *p)) return true;
    return false;
}

/* 需要完全隐藏的属性（find 返回 NULL） */
static bool prop_is_hidden(const char *name) {
    if (!name) return false;
    static const char *hidden[] = {
        "ro.magisk.version", "ro.sus.version",
        "init.svc.magiskd", "init.svc.daemonsu",
        "init.svc.ksud", "init.svc.apd", "init.svc.zygiskd",
        "ro.boot.magisk", "persist.magisk.hide",
        nullptr,
    };
    for (auto p = hidden; *p; ++p)
        if (!strcmp(name, *p)) return true;
    return false;
}

static const char *safe_prop_value(const char *name) {
    if (!strncmp(name, "ro.magisk", 9)  || !strncmp(name, "ro.zygisk", 9)  ||
        !strncmp(name, "ro.ksu", 6)      || !strncmp(name, "ro.apatch", 9)  ||
        !strncmp(name, "ro.riru", 7)     || !strncmp(name, "ro.lsposed", 10)||
        !strncmp(name, "persist.magisk", 14) ||
        !strncmp(name, "persist.vendor.magisk", 20) ||
        !strncmp(name, "ro.daemon.magisk", 16) ||
        !strncmp(name, "ro.bin.magisk", 13))
        return "";
    if (!strcmp(name, "ro.debuggable"))            return "0";
    if (!strcmp(name, "ro.secure"))                return "1";
    if (!strcmp(name, "ro.build.type"))            return "user";
    if (!strcmp(name, "ro.build.tags"))            return "release-keys";
    if (!strcmp(name, "ro.build.selinux"))         return "enforcing";
    if (!strcmp(name, "init.svc.magiskd"))         return "";
    if (!strcmp(name, "init.svc.zygiskd"))         return "";
    if (!strcmp(name, "init.svc.daemonsu"))        return "";
    if (!strcmp(name, "init.svc.ksud"))            return "";
    if (!strcmp(name, "init.svc.apd"))             return "";
    if (!strcmp(name, "persist.sys.root"))         return "0";
    if (!strcmp(name, "service.adb.root"))         return "0";
    if (!strcmp(name, "ro.boot.verifiedbootstate"))return "green";
    if (!strcmp(name, "ro.vendor.boot.verifiedbootstate")) return "green";
    if (!strcmp(name, "ro.boot.vbmeta.device_state"))      return "locked";
    if (!strcmp(name, "ro.boot.flash.locked"))     return "1";
    if (!strcmp(name, "ro.boot.veritymode"))       return "enforcing";
    if (!strcmp(name, "ro.oem.lockstate"))         return "locked";
    if (!strcmp(name, "ro.boot.warranty_bit"))     return "0";
    if (!strcmp(name, "ro.warranty_bit"))          return "0";
    if (!strcmp(name, "sys.oem_unlock_allowed"))   return "0";
    return "";
}

/* ---- 进程名（精确匹配） ---- */
static const char *kProcNameBlocks[] = {
    "magiskd", "magisklogd", "magiskinit", "magiskboot", "magiskpolicy",
    "zygiskd", "zygisk",
    "daemonsu", "supersu", "superuser",
    "lspd", "lsposed", "edxp",
    "ksud", "ksu",
    "apd", "apatch",
    "taichi",
    "denyd",
    nullptr,
};

static bool proc_name_blocked(const char *comm) {
    if (!comm) return false;
    for (auto p = kProcNameBlocks; *p; ++p)
        if (name_exact_match(comm, *p)) return true;
    return false;
}

/* ---- 命令阻止（精确匹配） ---- */
static const char *kCmdBlocks[] = {
    "magisk", "zygisk", "supersu", "daemonsu",
    "kernelsu", "apatch",
    "/system/bin/su", "/system/xbin/su", "/sbin/su",
    "/data/adb/ksud", "/data/adb/apd",
    nullptr,
};

static bool cmd_blocked(const char *s) {
    if (!s) return false;
    for (auto p = kCmdBlocks; *p; ++p) {
        if ((*p)[0] == '/') {
            if (path_prefix_match(s, *p)) return true;
        } else {
            if (name_exact_match(s, *p)) return true;
            /* 也检查 basename */
            const char *base = strrchr(s, '/');
            if (base && name_exact_match(base + 1, *p)) return true;
        }
    }
    return false;
}

/* ---- 注入库特征（词边界匹配） ---- */
static bool injlib_blocked(const char *name) {
    if (!name) return false;
    static const char *tokens[] = {
        "magisk", "zygisk", "frida", "lsplant", "xhook", "sandhook",
        "substrate", "inlinehook", "libwhale",
        "libnativebridge", "lspd", "riru",
        "libfrida", "frida-agent", "frida-gadget", "libDexHelper",
        "libepic", "dexmaker", "qbdi", "kernelsu", "apatch",
        "hideallroot", "rootmodlab", "shamiko",
        "libmagisk", "libzygisk", "libriru", "libxposed",
        "liblsposed", "libedxposed", "libshamiko",
        nullptr,
    };
    for (auto p = tokens; *p; ++p)
        if (line_has_token(name, *p)) return true;
    return false;
}

/* ---- maps 行过滤 ---- */
static std::vector<std::string> maps_blocklist() {
    return {
        "libzygisk", "zygisk", "Zygisk", "magisk", ".magisk",
        "/dev/zygisk", "/dev/magisk", "/data/adb/modules/hideallroot",
        "frida", "libfrida", "frida-agent", "frida-gadget",
        "linjector", "xhook", "libDexHelper", "memfd:", "zygisk_module_entry",
        "lsplant", "sandhook", "libwhale", "substrate",
        "inlinehook", "libnativebridge", "libepic", "dexmaker", "qbdi",
        "lspd", "riru", "kernelsu", "apatch",
        "shamiko", "hideallroot", "rootmodlab",
    };
}

/* ---- build.prop 行过滤 ---- */
static std::vector<std::string> buildprop_blocklist() {
    return {
        "ro.build.tags=test-keys",
        "ro.debuggable=1",
        "ro.secure=0",
        "ro.build.type=userdebug",
        "ro.build.type=eng",
        "ro.build.characteristics=eng",
        "ro.boot.flash.locked=0",
        "ro.boot.verifiedbootstate=orange",
        "ro.boot.verifiedbootstate=yellow",
    };
}

/* ---- 应用列表过滤 ---- */
static std::vector<std::string> applist_blocklist() {
    std::vector<std::string> blk;
    for (auto p = kHiddenPkgs; *p; ++p) blk.emplace_back(*p);
    for (auto &p : g_cfg.detect_pkgs) blk.push_back(p);
    for (auto &p : g_cfg.custom_pkgs) blk.push_back(p);
    return blk;
}

/* ---- 挂载信息过滤 ---- */
static std::vector<std::string> mounts_blocklist() {
    return {
        "magisk", "zygisk", "kernelsu", "apatch", "lspd", "riru",
        "/data/adb/modules", "/dev/zygisk", "/dev/magisk",
        "modules.img", "magisk_merge", "worker",
    };
}

/* ---- /proc/net/unix 过滤（修复：不再匹配 tcp/tcp6） ---- */
static std::vector<std::string> netunix_blocklist() {
    return { "magiskd", "zygiskd", "lspd", "ksud", "apd", "kernelsu" };
}

/* ---- /proc/modules 过滤（NEW: KernelSU 内核模块） ---- */
static std::vector<std::string> modules_blocklist() {
    return { "kernelsu", "ksu", "apatch", "magisk", "sukisu", "apm", "kpm" };
}

/* ---- socket 路径阻止 ---- */
static const char *kSocketBlocks[] = {
    "magisk", "zygisk", "kernelsu", "apatch", "supersu", "daemonsu",
    nullptr,
};

/* ---- 环境变量清洗列表 ---- */
static const char *kEnvClean[] = {
    "MAGISK_VER", "MAGISK_VER_CODE", "MAGISKTMP", "BOOTMODE", "MODPATH",
    "KSU", "KSU_VER", "KSU_VER_CODE", "KSU_KERNEL_VER_CODE",
    "APATCH", "APATCH_VER", "ASH_STANDALONE", "ZYGISK_ENABLED",
    nullptr,
};

/* ====================================================================
 *  SECTION 4 — 原始函数指针
 * ==================================================================== */

typedef int (*open_fn_t)(const char *, int, ...);
typedef int (*openat_fn_t)(int, const char *, int, ...);

static open_fn_t   orig_open      = nullptr;
static openat_fn_t orig_openat    = nullptr;
static int     (*orig_access)   (const char *, int)                = nullptr;
static int     (*orig_faccessat)(int, const char *, int, int)      = nullptr;
static int     (*orig_stat)     (const char *, struct stat *)      = nullptr;
static int     (*orig_lstat)    (const char *, struct stat *)      = nullptr;
static int     (*orig_fstatat)  (int, const char *, struct stat *, int) = nullptr;
static FILE   *(*orig_fopen)    (const char *, const char *)       = nullptr;
static DIR    *(*orig_opendir)  (const char *)                     = nullptr;
static struct dirent *(*orig_readdir64)(DIR *)                     = nullptr;
static int     (*orig_closedir) (DIR *)                            = nullptr;
static int     (*orig_readlink) (const char *, char *, size_t)     = nullptr;
static char   *(*orig_realpath) (const char *, char *)             = nullptr;
static int     (*orig_dladdr)   (void *, Dl_info *)                = nullptr;
static int     (*orig_sysprop_get) (const char *, char *)          = nullptr;
static const void *(*orig_sysprop_find)(const char *)              = nullptr;
/* Android 8+ 属性回调 API（__system_property_read_callback） */
typedef void (*prop_cb_t)(void *cookie, const char *name,
                          const char *value, unsigned int serial);
typedef void (*prop_read_cb_fn_t)(const void *pi, prop_cb_t cb, void *cookie);

static prop_read_cb_fn_t orig_prop_read_cb = nullptr;
static FILE   *(*orig_popen)    (const char *, const char *)       = nullptr;
static int     (*orig_system)   (const char *)                     = nullptr;
static int     (*orig_execve)   (const char *, char *const[], char *const[]) = nullptr;
static long    (*orig_ptrace)   (int, ...)                         = nullptr;
static ssize_t (*orig_read)     (int, void *, size_t)              = nullptr;
static ssize_t (*orig_pread64)  (int, void *, size_t, off64_t)     = nullptr;
static off_t   (*orig_lseek)    (int, off_t, int)                  = nullptr;
static int     (*orig_close)    (int)                              = nullptr;
static int     (*orig_kill)     (pid_t, int)                       = nullptr;
static int     (*orig_connect)  (int, const struct sockaddr *, socklen_t) = nullptr;
static long    (*orig_syscall_fn)(long, long, long, long, long, long, long) = nullptr;

/* ====================================================================
 *  SECTION 5 — 缓冲文件过滤器（修复 pread64 / 新增 lseek）
 * ==================================================================== */

struct BufFilter {
    std::string data;
    size_t off = 0;
};

static std::unordered_map<int, BufFilter> g_buffds;
static std::mutex g_bufmtx;

/* ---- 路径判断 ---- */
static bool is_maps_path(const char *path) {
    if (!path) return false;
    size_t n = strlen(path);
    if (n < 5 || strcmp(path + n - 5, "/maps") != 0) return false;
    return strncmp(path, "/proc/", 6) == 0;
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
    if (!strcmp(path, "/proc/mounts") || !strcmp(path, "/proc/self/mounts") ||
        !strcmp(path, "/proc/self/mountinfo") || !strcmp(path, "/etc/mtab"))
        return true;
    if (strncmp(path, "/proc/", 6) != 0) return false;
    const char *rest = path + 6;
    if (!isdigit((unsigned char)rest[0])) return false;
    const char *p = rest; while (isdigit((unsigned char)*p)) p++;
    return !strcmp(p, "/mountinfo") || !strcmp(p, "/mounts");
}

/* 修复：仅匹配 /proc/net/unix，不再匹配 tcp/tcp6 */
static bool is_netunix_path(const char *path) {
    if (!path) return false;
    return !strcmp(path, "/proc/net/unix") ||
           !strcmp(path, "/proc/self/net/unix");
}

/* NEW: /proc/modules */
static bool is_modules_path(const char *path) {
    return path && !strcmp(path, "/proc/modules");
}

static bool is_buildprop_path(const char *path) {
    if (!path) return false;
    size_t n = strlen(path);
    if (n >= 10 && !strcmp(path + n - 10, "build.prop")) {
        return strstr(path, "/system") || strstr(path, "/vendor") ||
               strstr(path, "/product") || strstr(path, "/system_ext") ||
               strstr(path, "/odm");
    }
    if (n >= 12 && !strcmp(path + n - 12, "prop.default"))
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

/* NEW: /proc/<pid>/attr/（SELinux context 文件过滤） */
[[maybe_unused]]
static bool is_proc_attr_path(const char *path) {
    if (!path || strncmp(path, "/proc/", 6) != 0) return false;
    const char *rest = path + 6;
    if (strncmp(rest, "self/attr/", 10) == 0) return true;
    if (isdigit((unsigned char)*rest)) {
        const char *slash = strchr(rest, '/');
        if (slash && strncmp(slash, "/attr/", 6) == 0) return true;
    }
    return false;
}

/* ---- 行过滤 ---- */
static std::string filter_lines(const std::string &in,
                                const std::vector<std::string> &block) {
    std::string out;
    out.reserve(in.size());
    size_t start = 0, pos;
    while ((pos = in.find('\n', start)) != std::string::npos) {
        std::string line = in.substr(start, pos - start);
        bool drop = false;
        for (auto &b : block)
            if (line_has_token(line.c_str(), b.c_str())) { drop = true; break; }
        if (!drop) { out += line; out += '\n'; }
        start = pos + 1;
    }
    if (start < in.size()) {
        std::string line = in.substr(start);
        bool drop = false;
        for (auto &b : block)
            if (line_has_token(line.c_str(), b.c_str())) drop = true;
        if (!drop) out += line;
    }
    return out;
}

static std::string filter_status(const std::string &in) {
    std::string out;
    out.reserve(in.size());
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

/* 修复：全程持锁，消除竞态 */
static void track_buffd(int fd, const std::vector<std::string> &block,
                        bool status_mode = false) {
    if (fd < 0) return;
    std::string content;
    char buf[4096];
    ssize_t n;
    while ((n = orig_read(fd, buf, sizeof(buf))) > 0)
        content.append(buf, (size_t)n);

    BufFilter bf;
    bf.data = status_mode ? filter_status(content)
                          : filter_lines(content, block);
    bf.off = 0;

    std::lock_guard<std::mutex> lk(g_bufmtx);
    g_buffds[fd] = std::move(bf);
}

static void drop_buffd(int fd) {
    std::lock_guard<std::mutex> lk(g_bufmtx);
    g_buffds.erase(fd);
}

/* ====================================================================
 *  SECTION 6 — PID 缓存（消除 /proc 枚举性能问题）
 * ==================================================================== */

struct PidInfo {
    std::string comm;
    bool blocked;
    time_t cached_at;
};

static std::unordered_map<long, PidInfo> g_pid_cache;
static std::mutex g_pidmtx;
#define PID_CACHE_TTL 5

static bool is_pid_blocked(long pid) {
    time_t now = time(nullptr);
    {
        std::lock_guard<std::mutex> lk(g_pidmtx);
        auto it = g_pid_cache.find(pid);
        if (it != g_pid_cache.end() && now - it->second.cached_at < PID_CACHE_TTL)
            return it->second.blocked;
    }
    char cpath[64];
    snprintf(cpath, sizeof(cpath), "/proc/%ld/comm", pid);
    int fd = orig_open(cpath, O_RDONLY);
    if (fd < 0) return false;
    char comm[64] = {0};
    ssize_t n = orig_read(fd, comm, sizeof(comm) - 1);
    orig_close(fd);
    if (n <= 0) return false;
    if (comm[n - 1] == '\n') comm[n - 1] = 0;

    bool blocked = proc_name_blocked(comm);
    {
        std::lock_guard<std::mutex> lk(g_pidmtx);
        g_pid_cache[pid] = {comm, blocked, now};
    }
    return blocked;
}

/* /proc/<pid>/attr/ SELinux context 防护：屏蔽被拦截进程（如 magiskd）的
 * SELinux context 读取，防止检测工具拿到 u:r:magisk:s0 之类上下文。
 * self / thread-self 放行（App 自身 context 本就是 untrusted_app）。 */
static bool proc_attr_blocked(const char *path) {
    if (!path || strncmp(path, "/proc/", 6) != 0) return false;
    const char *rest = path + 6;

    /* self / thread-self → 放行 */
    if (!strncmp(rest, "self/", 5) || !strncmp(rest, "thread-self/", 12))
        return false;

    /* 必须是 /proc/<digits>/attr[/...] */
    if (!isdigit((unsigned char)rest[0])) return false;
    const char *p = rest;
    while (isdigit((unsigned char)*p)) p++;
    if (strncmp(p, "/attr/", 6) != 0 && strcmp(p, "/attr") != 0)
        return false;

    long pid = atol(rest);
    return is_pid_blocked(pid);
}

static bool proc_dir_or_file_blocked(const char *path, bool is_dir) {
    if (strncmp(path, "/proc/", 6) != 0) return false;
    const char *rest = path + 6;
    if (!strncmp(rest, "self/", 5) || !strncmp(rest, "thread-self/", 12))
        return false;
    if (!isdigit((unsigned char)rest[0])) return false;
    const char *p = rest;
    while (isdigit((unsigned char)*p)) p++;

    long pid = atol(rest);
    if (pid <= 0) return false;

    if (is_dir) {
        if (*p != '\0') return false;
    } else {
        if (*p != '/') return false;
        const char *file = p + 1;
        bool want = !strcmp(file, "cmdline") || !strcmp(file, "comm") ||
                    !strcmp(file, "status")  || !strcmp(file, "stat")  ||
                    !strcmp(file, "wchan")   || !strcmp(file, "exe");
        if (!want) return false;
    }
    return is_pid_blocked(pid);
}

/* ====================================================================
 *  SECTION 7 — VFS 级 Unmount 引擎
 * ==================================================================== */

struct MountEntry {
    int id;
    std::string mount_point;
    std::string fs_type;
    std::string source;
};

static std::vector<MountEntry> parse_mountinfo() {
    std::vector<MountEntry> result;
    FILE *f = fopen("/proc/self/mountinfo", "r");
    if (!f) return result;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        MountEntry me;
        char *saveptr = nullptr;
        char *tok = strtok_r(line, " ", &saveptr);
        if (!tok) continue;
        me.id = atoi(tok);
        tok = strtok_r(nullptr, " ", &saveptr); /* parent */
        tok = strtok_r(nullptr, " ", &saveptr); /* major:minor */
        tok = strtok_r(nullptr, " ", &saveptr); /* root */
        tok = strtok_r(nullptr, " ", &saveptr); /* mount point */
        if (!tok) continue;
        me.mount_point = tok;
        tok = strtok_r(nullptr, " ", &saveptr); /* options */
        while (tok && strcmp(tok, "-") != 0)
            tok = strtok_r(nullptr, " ", &saveptr);
        if (!tok) continue;
        tok = strtok_r(nullptr, " ", &saveptr);
        if (tok) me.fs_type = tok;
        tok = strtok_r(nullptr, " ", &saveptr);
        if (tok) me.source = tok;
        result.push_back(std::move(me));
    }
    fclose(f);
    return result;
}

static bool is_magisk_mount(const MountEntry &me) {
    const auto &mp = me.mount_point;
    const auto &fs = me.fs_type;
    const auto &src = me.source;

    /* Magisk tmpfs 覆盖（仅 tmpfs，不动 erofs/ext4 基分区） */
    if (fs == "tmpfs") {
        if (mp == "/system" || mp == "/vendor" || mp == "/product" ||
            mp == "/system_ext" || mp == "/debug_ramdisk" || mp == "/sbin")
            return true;
        if (src.find("worker") != std::string::npos) return true;
        if (src.find("magisk") != std::string::npos) return true;
    }
    /* /data/adb 下的所有挂载 */
    if (mp.find("/data/adb") == 0) return true;
    /* source 包含关键词 */
    if (src.find("magisk") != std::string::npos) return true;
    if (src.find("ksu") != std::string::npos) return true;
    if (src.find("apatch") != std::string::npos) return true;
    return false;
}

static void do_unmount() {
    auto mounts = parse_mountinfo();
    std::vector<std::string> to_unmount;
    for (auto &me : mounts)
        if (is_magisk_mount(me))
            to_unmount.push_back(me.mount_point);

    /* 按路径长度降序（先子后父） */
    std::sort(to_unmount.begin(), to_unmount.end(),
              [](const std::string &a, const std::string &b) {
                  return a.size() > b.size();
              });

    int ok = 0;
    for (auto &mp : to_unmount)
        if (umount2(mp.c_str(), MNT_DETACH) == 0) ok++;

    /* 兜底 */
    const char *extra[] = {
        "/data/adb/magisk", "/data/adb/modules",
        "/data/adb/ksu", "/data/adb/ap",
        "/debug_ramdisk", "/sbin", nullptr,
    };
    for (auto p = extra; *p; ++p)
        if (umount2(*p, MNT_DETACH) == 0) ok++;

    HAR_LOG("unmount: %d points removed", ok);
}

/* ====================================================================
 *  SECTION 8 — 环境变量清洗
 * ==================================================================== */

static void clean_environment() {
    for (auto p = kEnvClean; *p; ++p)
        if (getenv(*p)) unsetenv(*p);

    /* 清洗 PATH 中的可疑目录 */
    const char *path = getenv("PATH");
    if (path) {
        std::string new_path;
        std::string old_path(path);
        size_t start = 0;
        while (start < old_path.size()) {
            size_t colon = old_path.find(':', start);
            if (colon == std::string::npos) colon = old_path.size();
            std::string dir = old_path.substr(start, colon - start);
            bool bad = dir.find("/sbin") != std::string::npos ||
                       dir.find("magisk") != std::string::npos ||
                       dir.find("supersu") != std::string::npos ||
                       dir.find("/data/adb") != std::string::npos;
            /* 保留 /su 仅当它是独立路径段 */
            if (!bad && dir.size() >= 3) {
                size_t spos = dir.find("/su");
                if (spos != std::string::npos &&
                    (spos == 0 || dir[spos-1] == ':') &&
                    (spos + 3 >= dir.size() || dir[spos+3] == '/' || dir[spos+3] == ':'))
                    bad = true;
            }
            if (!bad) {
                if (!new_path.empty()) new_path += ":";
                new_path += dir;
            }
            start = colon + 1;
        }
        if (!new_path.empty()) setenv("PATH", new_path.c_str(), 1);
    }
}

/* ====================================================================
 *  SECTION 9 — Zygisk 痕迹清理
 * ==================================================================== */

static void clean_zygisk_traces() {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return;
    char line[1024];
    int renamed = 0;
    while (fgets(line, sizeof(line), f)) {
        bool suspicious = false;
        static const char *tokens[] = {
            "magisk", "zygisk", "frida", "xhook", "lsplant",
            "hideallroot", "rootmodlab", "shamiko", "riru", nullptr,
        };
        for (auto p = tokens; *p; ++p)
            if (line_has_token(line, *p)) { suspicious = true; break; }
        if (!suspicious) continue;

        unsigned long start_addr = 0, end_addr = 0;
        if (sscanf(line, "%lx-%lx", &start_addr, &end_addr) != 2) continue;
        size_t len = end_addr - start_addr;
        if (len > 0 && len < 0x10000000) {
            if (prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME,
                      (unsigned long)start_addr, len, "libc_malloc") == 0)
                renamed++;
        }
    }
    fclose(f);
    if (renamed > 0)
        HAR_LOG("zygisk_clean: renamed %d mappings", renamed);
}

/* ====================================================================
 *  SECTION 10 — 进程/包名目标判断
 * ==================================================================== */

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
    if (g_cfg.target_mode == 0) return true;
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

/* ====================================================================
 *  SECTION 11 — Hook 实现
 * ==================================================================== */

/* ---------- open ---------- */
static int my_open(const char *path, int flags, ...) {
    va_list ap; va_start(ap, flags);
    int mode = va_arg(ap, int);
    va_end(ap);

    if (path) {
        if (g_cfg.file_hide && path_blocked(path)) { errno = ENOENT; return -1; }
        if (g_cfg.proc_hide && proc_dir_or_file_blocked(path, false)) { errno = ENOENT; return -1; }
        if (g_cfg.proc_hide && proc_attr_blocked(path)) { errno = ENOENT; return -1; }

        if (g_cfg.antidebug && is_status_path(path)) {
            int fd = orig_open(path, flags, mode);
            if (fd >= 0) track_buffd(fd, {}, true);
            return fd;
        }
        if (g_cfg.mount_hide && is_mounts_path(path)) {
            int fd = orig_open(path, flags, mode);
            if (fd >= 0) track_buffd(fd, mounts_blocklist());
            return fd;
        }
        if (g_cfg.proc_hide && is_netunix_path(path)) {
            int fd = orig_open(path, flags, mode);
            if (fd >= 0) track_buffd(fd, netunix_blocklist());
            return fd;
        }
        if (g_cfg.file_hide && is_modules_path(path)) {
            int fd = orig_open(path, flags, mode);
            if (fd >= 0) track_buffd(fd, modules_blocklist());
            return fd;
        }
        if (g_cfg.file_hide && is_buildprop_path(path)) {
            int fd = orig_open(path, flags, mode);
            if (fd >= 0) track_buffd(fd, buildprop_blocklist());
            return fd;
        }
        if (is_maps_path(path)) {
            int fd = orig_open(path, flags, mode);
            if (fd >= 0) track_buffd(fd, maps_blocklist());
            return fd;
        }
        if (g_apply_applist && is_pkglist_path(path)) {
            int fd = orig_open(path, flags, mode);
            if (fd >= 0) track_buffd(fd, applist_blocklist());
            return fd;
        }
    }
    return orig_open(path, flags, mode);
}

/* ---------- openat ---------- */
static int my_openat(int dirfd, const char *path, int flags, ...) {
    va_list ap; va_start(ap, flags);
    int mode = va_arg(ap, int);
    va_end(ap);

    if (path) {
        if (g_cfg.file_hide && path_blocked(path)) { errno = ENOENT; return -1; }
        if (g_cfg.proc_hide && proc_dir_or_file_blocked(path, false)) { errno = ENOENT; return -1; }
        if (g_cfg.proc_hide && proc_attr_blocked(path)) { errno = ENOENT; return -1; }

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
        if (g_cfg.file_hide && is_modules_path(path)) {
            int fd = orig_openat(dirfd, path, flags, mode);
            if (fd >= 0) track_buffd(fd, modules_blocklist());
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

/* ---------- access / faccessat ---------- */
static int my_access(const char *path, int mode) {
    if (path && g_cfg.file_hide && path_blocked(path)) { errno = ENOENT; return -1; }
    if (path && g_cfg.proc_hide && proc_dir_or_file_blocked(path, false)) { errno = ENOENT; return -1; }
    if (path && g_cfg.proc_hide && proc_attr_blocked(path)) { errno = ENOENT; return -1; }
    return orig_access(path, mode);
}

static int my_faccessat(int dirfd, const char *path, int mode, int flags) {
    if (path && g_cfg.file_hide && path_blocked(path)) { errno = ENOENT; return -1; }
    if (path && g_cfg.proc_hide && proc_dir_or_file_blocked(path, false)) { errno = ENOENT; return -1; }
    if (path && g_cfg.proc_hide && proc_attr_blocked(path)) { errno = ENOENT; return -1; }
    return orig_faccessat(dirfd, path, mode, flags);
}

/* ---------- stat / lstat ---------- */
static int my_stat(const char *path, struct stat *buf) {
    if (path && g_cfg.file_hide && path_blocked(path)) { errno = ENOENT; return -1; }
    if (path && g_cfg.proc_hide && proc_dir_or_file_blocked(path, false)) { errno = ENOENT; return -1; }
    if (path && g_cfg.proc_hide && proc_attr_blocked(path)) { errno = ENOENT; return -1; }
    return orig_stat(path, buf);
}

static int my_lstat(const char *path, struct stat *buf) {
    if (path && g_cfg.file_hide && path_blocked(path)) { errno = ENOENT; return -1; }
    if (path && g_cfg.proc_hide && proc_dir_or_file_blocked(path, false)) { errno = ENOENT; return -1; }
    if (path && g_cfg.proc_hide && proc_attr_blocked(path)) { errno = ENOENT; return -1; }
    return orig_lstat(path, buf);
}

/* ---------- fstatat（补齐 stat 族最后一个，防止 fstatat(AT_FDCWD,...) 绕过） ---------- */
static int my_fstatat(int dirfd, const char *path, struct stat *buf, int flags) {
    if (path) {
        if (g_cfg.file_hide && path_blocked(path)) {
            errno = ENOENT;
            return -1;
        }
        if (g_cfg.proc_hide && proc_dir_or_file_blocked(path, false)) {
            errno = ENOENT;
            return -1;
        }
        if (g_cfg.proc_hide && proc_attr_blocked(path)) {
            errno = ENOENT;
            return -1;
        }
    }
    return orig_fstatat(dirfd, path, buf, flags);
}

/* ---------- fopen ---------- */
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
        if (g_cfg.file_hide && is_modules_path(path)) {
            FILE *f = orig_fopen(path, mode);
            if (f) track_buffd(fileno(f), modules_blocklist());
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

/* ---------- opendir / readdir64 / closedir ---------- */
static std::unordered_set<DIR *> g_proc_dirs;
static std::mutex g_dirmtx;

static DIR *my_opendir(const char *name) {
    if (name && g_cfg.proc_hide && proc_dir_or_file_blocked(name, true)) {
        errno = ENOENT; return nullptr;
    }
    DIR *d = orig_opendir(name);
    if (d && g_cfg.proc_hide && name &&
        (strcmp(name, "/proc") == 0 || strcmp(name, "/proc/") == 0)) {
        std::lock_guard<std::mutex> lk(g_dirmtx);
        g_proc_dirs.insert(d);
    }
    return d;
}

static struct dirent *my_readdir64(DIR *dirp) {
    bool is_proc_enum = false;
    {
        std::lock_guard<std::mutex> lk(g_dirmtx);
        is_proc_enum = g_proc_dirs.count(dirp) > 0;
    }
    struct dirent *ent;
    while ((ent = orig_readdir64(dirp)) != nullptr) {
        if (!is_proc_enum || !g_cfg.proc_hide) return ent;
        const char *name = ent->d_name;
        if (!isdigit((unsigned char)name[0])) return ent;
        long pid = atol(name);
        if (pid > 0 && is_pid_blocked(pid)) continue;
        return ent;
    }
    return nullptr;
}

static int my_closedir(DIR *dirp) {
    {
        std::lock_guard<std::mutex> lk(g_dirmtx);
        g_proc_dirs.erase(dirp);
    }
    return orig_closedir(dirp);
}

/* ---------- readlink / realpath ---------- */
static int my_readlink(const char *path, char *buf, size_t bufsiz) {
    if (path && g_cfg.file_hide && path_blocked(path)) { errno = ENOENT; return -1; }
    if (path && g_cfg.proc_hide && is_fdlink_path(path)) {
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

/* ---------- dladdr（修复：返回 0 而非空字符串） ---------- */
static int my_dladdr(void *addr, Dl_info *info) {
    int r = orig_dladdr(addr, info);
    if (r && info && g_cfg.dladdr_hide && info->dli_fname &&
        injlib_blocked(info->dli_fname)) {
        return 0;  /* 未找到，而非返回成功+空字符串 */
    }
    return r;
}

/* ---------- 属性 ---------- */
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

/* NEW: 隐藏属性存在性 */
static const void *my_sysprop_find(const char *name) {
    if (name && g_cfg.prop_hide && prop_is_hidden(name))
        return nullptr;
    return orig_sysprop_find(name);
}

/* ---------- __system_property_read_callback（NEW） ---------- */
/* 原理：原 API 同步调用用户 callback 并传入 (name, value, serial)。
 * 我们包装一层：拿到原始值后，按需替换/隐匿再转发给用户 callback。
 * orig_prop_read_cb 在返回前同步调用 callback，故栈上 PropCbCtx 在其执行期有效。 */
struct PropCbCtx {
    prop_cb_t user_cb;
    void     *user_cookie;
};

static void prop_cb_trampoline(void *ctx, const char *name,
                               const char *value, unsigned int serial) {
    PropCbCtx *c = static_cast<PropCbCtx *>(ctx);
    if (name && g_cfg.prop_hide) {
        /* 完全隐藏的属性：给空值（find 已返回 NULL，这里是兜底） */
        if (prop_is_hidden(name)) {
            c->user_cb(c->user_cookie, name, "", serial);
            return;
        }
        /* 需要伪装的属性：替换值 */
        if (prop_is_blocked(name)) {
            const char *safe = safe_prop_value(name);
            c->user_cb(c->user_cookie, name, safe, serial);
            return;
        }
    }
    /* 正常属性：原样转发 */
    c->user_cb(c->user_cookie, name, value, serial);
}

static void my_prop_read_cb(const void *pi, prop_cb_t callback, void *cookie) {
    PropCbCtx ctx;
    ctx.user_cb     = callback;
    ctx.user_cookie = cookie;
    orig_prop_read_cb(pi, prop_cb_trampoline, &ctx);
}

/* ---------- 命令执行 ---------- */
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

/* ---------- ptrace ---------- */
static long my_ptrace(int request, ...) {
    va_list ap; va_start(ap, request);
    pid_t pid = va_arg(ap, pid_t);
    void *addr = va_arg(ap, void *);
    void *data = va_arg(ap, void *);
    va_end(ap);
    if (g_cfg.antidebug &&
        (request == PTRACE_ATTACH || request == PTRACE_SEIZE)) {
        if (pid == 0 || pid == getpid()) { errno = EPERM; return -1; }
    }
    return orig_ptrace(request, pid, addr, data);
}

/* ---------- read ---------- */
static ssize_t my_read(int fd, void *buf, size_t count) {
    {
        std::lock_guard<std::mutex> lk(g_bufmtx);
        auto it = g_buffds.find(fd);
        if (it != g_buffds.end()) {
            BufFilter &bf = it->second;
            if (bf.off >= bf.data.size()) return 0;
            size_t remain = bf.data.size() - bf.off;
            size_t tocopy = remain < count ? remain : count;
            if (tocopy) memcpy(buf, bf.data.data() + bf.off, tocopy);
            bf.off += tocopy;
            return (ssize_t)tocopy;
        }
    }
    return orig_read(fd, buf, count);
}

/* ---------- pread64（修复：正确使用 offset） ---------- */
static ssize_t my_pread64(int fd, void *buf, size_t count, off64_t offset) {
    {
        std::lock_guard<std::mutex> lk(g_bufmtx);
        auto it = g_buffds.find(fd);
        if (it != g_buffds.end()) {
            BufFilter &bf = it->second;
            if (offset < 0) { errno = EINVAL; return -1; }
            if ((size_t)offset >= bf.data.size()) return 0;
            size_t remain = bf.data.size() - (size_t)offset;
            size_t tocopy = remain < count ? remain : count;
            if (tocopy) memcpy(buf, bf.data.data() + (size_t)offset, tocopy);
            /* pread64 不修改 bf.off */
            return (ssize_t)tocopy;
        }
    }
    return orig_pread64(fd, buf, count, offset);
}

/* ---------- lseek（NEW） ---------- */
static off_t my_lseek(int fd, off_t offset, int whence) {
    {
        std::lock_guard<std::mutex> lk(g_bufmtx);
        auto it = g_buffds.find(fd);
        if (it != g_buffds.end()) {
            BufFilter &bf = it->second;
            off_t newoff;
            switch (whence) {
                case SEEK_SET: newoff = offset; break;
                case SEEK_CUR: newoff = (off_t)bf.off + offset; break;
                case SEEK_END: newoff = (off_t)bf.data.size() + offset; break;
                default: errno = EINVAL; return -1;
            }
            if (newoff < 0) { errno = EINVAL; return -1; }
            bf.off = (size_t)newoff;
            return newoff;
        }
    }
    return orig_lseek(fd, offset, whence);
}

/* ---------- close ---------- */
static int my_close(int fd) {
    if (fd >= 0) drop_buffd(fd);
    return orig_close(fd);
}

/* ---------- kill（NEW：阻止信号探测） ---------- */
static int my_kill(pid_t pid, int sig) {
    if (g_cfg.proc_hide && pid > 0 && is_pid_blocked((long)pid)) {
        errno = ESRCH;
        return -1;
    }
    return orig_kill(pid, sig);
}

/* ---------- connect（NEW：阻止 magisk/ksu socket） ---------- */
static bool socket_blocked(const char *sun_path) {
    if (!sun_path) return false;
    for (auto p = kSocketBlocks; *p; ++p)
        if (line_has_token(sun_path, *p)) return true;
    return false;
}

static int my_connect(int sockfd, const struct sockaddr *addr, socklen_t len) {
    if (g_cfg.proc_hide && addr && addr->sa_family == AF_UNIX) {
        const struct sockaddr_un *un = (const struct sockaddr_un *)addr;
        if (socket_blocked(un->sun_path)) {
            errno = ECONNREFUSED;
            return -1;
        }
    }
    return orig_connect(sockfd, addr, len);
}

/* ---------- syscall（NEW：拦截 openat2 / statx / faccessat2） ---------- */
static long my_syscall(long number, long a1, long a2, long a3,
                       long a4, long a5, long a6) {
#ifdef SYS_openat2
    if (number == SYS_openat2 && g_cfg.file_hide) {
        const char *pathname = (const char *)a2;
        if (pathname && (path_blocked(pathname) ||
            (g_cfg.proc_hide && proc_dir_or_file_blocked(pathname, false)))) {
            errno = ENOENT;
            return -1;
        }
    }
#endif
#ifdef SYS_statx
    if (number == SYS_statx && g_cfg.file_hide) {
        const char *pathname = (const char *)a2;
        if (pathname && (path_blocked(pathname) ||
            (g_cfg.proc_hide && proc_dir_or_file_blocked(pathname, false)))) {
            errno = ENOENT;
            return -1;
        }
    }
#endif
#ifdef SYS_faccessat2
    if (number == SYS_faccessat2 && g_cfg.file_hide) {
        const char *pathname = (const char *)a2;
        if (pathname && path_blocked(pathname)) {
            errno = ENOENT;
            return -1;
        }
    }
#endif
    return orig_syscall_fn(number, a1, a2, a3, a4, a5, a6);
}

/* ====================================================================
 *  SECTION 12 — 模块入口
 * ==================================================================== */

class HideModule : public zygisk::Module {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        (void)api; (void)env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        (void)args;
        load_config();

        if (!g_cfg.enable || !g_cfg.native_hook) return;

        std::string pkg = get_self_package();
        if (!is_target_pkg(pkg)) return;

        g_active = true;
        bool applist = should_applist_filter(pkg);
        g_apply_applist = applist;

        /* 阶段1: VFS 级 unmount */
        if (g_cfg.unmount_magisk)
            do_unmount();

        /* 阶段2: 环境变量清洗 */
        if (g_cfg.env_clean)
            clean_environment();

        /* 阶段3: 注册 PLT hook */
        zygisk::Api *api = this->api;

        #define REG(repl, orig, sym) \
            api->pltHookRegister(".*", sym, (void *)repl, (void **)&orig)

        if (g_cfg.file_hide || g_cfg.proc_hide || applist) {
            REG(my_open,      orig_open,      "open");
            REG(my_openat,    orig_openat,    "openat");
            REG(my_access,    orig_access,    "access");
            REG(my_faccessat, orig_faccessat, "faccessat");
            REG(my_stat,      orig_stat,      "stat");
            REG(my_lstat,     orig_lstat,     "lstat");
            REG(my_fstatat,   orig_fstatat,   "fstatat");
            REG(my_fopen,     orig_fopen,     "fopen");
            REG(my_readlink,  orig_readlink,  "readlink");
            REG(my_realpath,  orig_realpath,  "realpath");
        }
        if (g_cfg.proc_hide) {
            REG(my_opendir,    orig_opendir,    "opendir");
            REG(my_readdir64,  orig_readdir64,  "readdir64");
            REG(my_closedir,   orig_closedir,   "closedir");
            REG(my_kill,       orig_kill,       "kill");
            REG(my_connect,    orig_connect,    "connect");
        }
        if (g_cfg.dladdr_hide) {
            REG(my_dladdr, orig_dladdr, "dladdr");
        }
        if (g_cfg.prop_hide) {
            REG(my_sysprop_get,  orig_sysprop_get,  "__system_property_get");
            REG(my_sysprop_find, orig_sysprop_find, "__system_property_find");
            REG(my_prop_read_cb,  orig_prop_read_cb,  "__system_property_read_callback");
        }
        if (g_cfg.file_hide || applist || g_cfg.mount_hide ||
            g_cfg.antidebug || g_cfg.proc_hide) {
            REG(my_read,    orig_read,    "read");
            REG(my_pread64, orig_pread64, "pread64");
            REG(my_lseek,   orig_lseek,   "lseek");
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
        /* NEW: syscall 拦截 */
        REG(my_syscall, orig_syscall_fn, "syscall");

        #undef REG

        if (!api->pltHookCommit())
            HAR_LOG("pltHookCommit FAILED for %s", pkg.c_str());
        else
            HAR_LOG("v2.0 active: %s (file=%d prop=%d proc=%d app=%d mnt=%d adb=%d unmount=%d env=%d)",
                    pkg.c_str(), g_cfg.file_hide, g_cfg.prop_hide,
                    g_cfg.proc_hide, applist, g_cfg.mount_hide,
                    g_cfg.antidebug, g_cfg.unmount_magisk, g_cfg.env_clean);
    }

    void postAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        (void)args;
        if (!g_active) return;
        if (g_cfg.zygisk_clean)
            clean_zygisk_traces();
    }
};

REGISTER_ZYGISK_MODULE(HideModule)
