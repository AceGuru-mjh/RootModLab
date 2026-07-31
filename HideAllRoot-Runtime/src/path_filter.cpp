#include "include/path_filter.h"
#include "include/logging.h"

#include <cstring>
#include <fstream>
#include <algorithm>
#include <sys/system_properties.h>

namespace har {

PathFilter::RuleSet PathFilter::g_rules;
int PathFilter::g_api_level = 0;
bool PathFilter::g_initialized = false;

// ═══════════════════════════════════════════════════════════
// 默认规则（覆盖 Magisk/KernelSU/APatch/Zygisk/LSPosed）
// ═══════════════════════════════════════════════════════════

void PathFilter::LoadDefaults() {
    auto& r = g_rules;

    // ─── 路径前缀（精确目录匹配）───
    r.path_prefixes = {
        // Magisk
        "/sbin/su", "/sbin/magisk",
        "/system/bin/su", "/system/xbin/su",
        "/system/etc/.magisk",
        "/data/adb/magisk",
        "/data/adb/modules",
        "/data/adb/magisk.img",
        "/data/adb/magisk.db",
        "/cache/.magisk",
        "/dev/.magisk",

        // KernelSU
        "/data/adb/ksu",
        "/data/adb/ksud",

        // APatch
        "/data/adb/ap",
        "/data/adb/apd",

        // Zygisk
        "/data/adb/modules/zygisk",

        // LSPosed
        "/data/adb/lspd",
        "/data/misc/lspd",

        // 通用 root 工具
        "/system/app/Superuser",
        "/system/app/SuperSU",
        "/system/app/KingRoot",
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su",

        // TWRP / Recovery
        "/cache/recovery",
        "/data/media/0/TWRP",

        // Magisk Manager / 隐藏后的包名
        "/data/user/0/com.topjohnwu.magisk",
        "/data/data/com.topjohnwu.magisk",

        // /debug_ramdisk（KernelSU 工作目录）
        "/debug_ramdisk",
    };

    // ─── 路径子串（模糊匹配）───
    r.path_substrings = {
        "magisk",
        "libzygisk",
        "libriru",
        "liblsposed",
        "libxposed",
        "libhar_runtime",   // 我们自己
        "kernelsu",
        "apatch",
        "supersu",
        "kingroot",
    };

    // ─── 进程名 ───
    r.process_names = {
        "magiskd",
        "magisk32",
        "magisk64",
        "magiskinit",
        "ksud",
        "apd",
        "zygisk",
        "lspd",
        "har_guard",
    };

    // ─── 挂载关键词 ───
    r.mount_keywords = {
        "magisk",
        "modules",
        "adb",
        "tmpfs /system",
        "tmpfs /vendor",
        "worker",           // Magisk 的 overlay worker
        "mirror",           // Magisk mirror
    };

    // ─── 环境变量关键词 ───
    r.environ_keywords = {
        "LD_PRELOAD",
        "MAGISK",
        "ZYGISK",
        "RIRU",
        "LSPOSED",
    };

    // ─── /proc/self/maps 行关键词 ───
    r.maps_keywords = {
        "magisk",
        "zygisk",
        "riru",
        "lsposed",
        "xposed",
        "har_runtime",
        "kernelsu",
        "apatch",
        "/data/adb",
        "/debug_ramdisk",
    };

    // ─── 目标包名（空 = 对所有 app 生效）───
    r.target_packages = {};  // 空 = 全部

    // ─── 白名单（这些包名不隐藏）───
    r.whitelist_packages = {
        "com.android.shell",          // adb shell 需要看到真实环境
        "io.github.vvb2060.momo",    // 调试时可临时加入白名单
    };

    g_api_level = android_get_device_api_level();
    g_initialized = true;

    LOG_I("PathFilter: loaded %zu prefixes, %zu substrings, %zu procs",
          r.path_prefixes.size(), r.path_substrings.size(), r.process_names.size());
}

// ═══════════════════════════════════════════════════════════
// 从配置文件加载（覆盖默认规则）
// ═══════════════════════════════════════════════════════════

bool PathFilter::LoadRules(const char* config_path) {
    // 先加载默认
    LoadDefaults();

    std::ifstream ifs(config_path);
    if (!ifs.is_open()) {
        LOG_W("PathFilter: config not found at %s, using defaults", config_path);
        return false;
    }

    std::string line;
    std::string section;

    while (std::getline(ifs, line)) {
        // 去除首尾空白
        auto start = line.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) continue;
        line = line.substr(start);
        auto end = line.find_last_not_of(" \t\r\n");
        if (end != std::string::npos) line = line.substr(0, end + 1);

        // 跳过注释
        if (line[0] == '#' || line[0] == ';') continue;

        // Section 头
        if (line[0] == '[') {
            auto close = line.find(']');
            if (close != std::string::npos) {
                section = line.substr(1, close - 1);
            }
            continue;
        }

        // 键值对
        auto eq = line.find('=');
        if (eq != std::string::npos) {
            std::string key = line.substr(0, eq);
            std::string val = line.substr(eq + 1);

            if (key == "ENABLED" && section.empty()) {
                g_rules.enabled = (val == "1" || val == "true");
            }
            continue;
        }

        // 纯路径/名称行（按 section 分类）
        if (section == "path_prefix") {
            g_rules.path_prefixes.push_back(line);
        } else if (section == "path_substring") {
            g_rules.path_substrings.push_back(line);
        } else if (section == "process") {
            g_rules.process_names.push_back(line);
        } else if (section == "mount") {
            g_rules.mount_keywords.push_back(line);
        } else if (section == "target_package") {
            g_rules.target_packages.push_back(line);
        } else if (section == "whitelist_package") {
            g_rules.whitelist_packages.push_back(line);
        }
    }

    LOG_I("PathFilter: config loaded from %s", config_path);
    return true;
}

// ═══════════════════════════════════════════════════════════
// 核心判断函数
// ═══════════════════════════════════════════════════════════

bool PathFilter::ShouldHidePath(const char* path) {
    if (!path || !g_rules.enabled) return false;
    return ShouldHidePath(std::string_view(path));
}

bool PathFilter::ShouldHidePath(std::string_view path) {
    if (!g_rules.enabled) return false;

    // 快速路径：首字符不是 '/' 的相对路径，检查子串
    if (!path.empty() && path[0] != '/') {
        return MatchSubstring(path, g_rules.path_substrings);
    }

    // 前缀匹配（O(n) 但 n 很小，~40 条规则）
    if (MatchPrefix(path, g_rules.path_prefixes)) return true;

    // 子串匹配（用于 /proc/self/fd/123 -> /data/adb/... 等情况）
    if (MatchSubstring(path, g_rules.path_substrings)) return true;

    return false;
}

bool PathFilter::ShouldHideLink(const char* path, const char* link_target) {
    if (!link_target) return false;

    // readlink("/proc/self/exe") 等：检查链接目标
    if (ShouldHidePath(link_target)) return true;

    // readlink("/proc/<pid>/fd/<n>")：检查 fd 指向
    if (path && strstr(path, "/fd/") && ShouldHidePath(link_target)) return true;

    return false;
}

bool PathFilter::ShouldFilterLine(const char* line, size_t len) {
    if (!line || len == 0) return false;

    std::string_view sv(line, len);
    return MatchSubstring(sv, g_rules.maps_keywords);
}

bool PathFilter::ShouldHideDentry(const char* dir_path, const char* name) {
    if (!name) return false;

    // /proc 目录下的 PID 目录：检查进程名
    if (dir_path && strcmp(dir_path, "/proc") == 0) {
        // 纯数字目录名 = PID，需要检查 /proc/<pid>/comm
        // 这里只做名称级过滤（如 "magisk" 等非数字条目）
        bool is_numeric = true;
        for (const char* p = name; *p; p++) {
            if (*p < '0' || *p > '9') { is_numeric = false; break; }
        }
        if (!is_numeric) {
            // 非数字条目：检查是否匹配进程名
            return ShouldHideProcess(name);
        }
        // 数字条目（PID）：由 ProcHider 处理
        return false;
    }

    // 其他目录：检查子串
    return MatchSubstring(std::string_view(name), g_rules.path_substrings);
}

bool PathFilter::ShouldHideProcess(const char* comm) {
    if (!comm) return false;
    for (const auto& name : g_rules.process_names) {
        if (strcmp(comm, name.c_str()) == 0) return true;
        // 也检查前缀（如 "magisk32" 匹配 "magisk"）
        if (strncmp(comm, name.c_str(), name.size()) == 0) return true;
    }
    return false;
}

bool PathFilter::ShouldFilterMount(const char* line, size_t len) {
    if (!line || len == 0) return false;
    std::string_view sv(line, len);
    return MatchSubstring(sv, g_rules.mount_keywords);
}

bool PathFilter::ShouldFilterEnviron(const char* entry, size_t len) {
    if (!entry || len == 0) return false;
    std::string_view sv(entry, len);
    return MatchSubstring(sv, g_rules.environ_keywords);
}

bool PathFilter::IsEnabled() {
    return g_rules.enabled;
}

bool PathFilter::ShouldHidePackage(const char* pkg_name) {
    if (!pkg_name) return false;

    // 白名单优先
    for (const auto& wp : g_rules.whitelist_packages) {
        if (strcmp(pkg_name, wp.c_str()) == 0) return false;
    }

    // 如果 target_packages 为空，对所有包生效
    if (g_rules.target_packages.empty()) return true;

    // 否则检查是否在目标列表中
    for (const auto& tp : g_rules.target_packages) {
        if (strcmp(pkg_name, tp.c_str()) == 0) return true;
    }
    return false;
}

int PathFilter::GetApiLevel() {
    return g_api_level;
}

// ═══════════════════════════════════════════════════════════
// 内部匹配函数
// ═══════════════════════════════════════════════════════════

bool PathFilter::MatchPrefix(std::string_view path,
                              const std::vector<std::string>& prefixes) {
    for (const auto& prefix : prefixes) {
        if (path.size() >= prefix.size() &&
            path.substr(0, prefix.size()) == prefix) {
            // 确保是完整路径段匹配
            // "/data/adb" 应匹配 "/data/adb/magisk" 但不匹配 "/data/adb2"
            if (path.size() == prefix.size()) return true;  // 精确匹配
            char next = path[prefix.size()];
            if (next == '/' || next == '\0') return true;
        }
    }
    return false;
}

bool PathFilter::MatchSubstring(std::string_view path,
                                 const std::vector<std::string>& substrs) {
    for (const auto& sub : substrs) {
        if (path.find(sub) != std::string_view::npos) {
            return true;
        }
    }
    return false;
}

} // namespace har
