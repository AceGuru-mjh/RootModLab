#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace har {

// ═══════════════════════════════════════════════════════════
// 路径过滤器：判断给定路径是否需要隐藏
// 线程安全：初始化后只读，无需加锁
// ═══════════════════════════════════════════════════════════

class PathFilter {
public:
    // 从配置文件加载规则
    // 格式：每行一个路径前缀，# 开头为注释
    static bool LoadRules(const char* config_path);

    // 使用内置默认规则（无需配置文件）
    static void LoadDefaults();

    // ─── 核心判断函数 ───

    // 文件路径是否需要隐藏（openat/faccessat/stat/statx）
    static bool ShouldHidePath(const char* path);
    static bool ShouldHidePath(std::string_view path);

    // 符号链接目标是否需要隐藏（readlinkat）
    static bool ShouldHideLink(const char* path, const char* link_target);

    // 文件内容中某行是否需要过滤（/proc/self/maps 等）
    static bool ShouldFilterLine(const char* line, size_t len);

    // 目录条目是否需要隐藏（getdents64）
    static bool ShouldHideDentry(const char* dir_path, const char* name);

    // 进程名是否需要隐藏（/proc/<pid>/comm）
    static bool ShouldHideProcess(const char* comm);

    // 挂载信息行是否需要过滤（/proc/mounts, mountinfo）
    static bool ShouldFilterMount(const char* line, size_t len);

    // 环境变量行是否需要过滤（/proc/self/environ）
    static bool ShouldFilterEnviron(const char* entry, size_t len);

    // ─── 配置查询 ───
    static bool IsEnabled();
    static bool ShouldHidePackage(const char* pkg_name);
    static int  GetApiLevel();

private:
    struct RuleSet {
        std::vector<std::string> path_prefixes;      // 路径前缀匹配
        std::vector<std::string> path_substrings;    // 路径子串匹配
        std::vector<std::string> process_names;      // 进程名
        std::vector<std::string> mount_keywords;     // 挂载关键词
        std::vector<std::string> environ_keywords;   // 环境变量关键词
        std::vector<std::string> maps_keywords;      // maps 行关键词
        std::vector<std::string> target_packages;    // 目标包名（空=全部）
        std::vector<std::string> whitelist_packages; // 白名单包名
        bool enabled = true;
    };

    static RuleSet g_rules;
    static int g_api_level;
    static bool g_initialized;

    static bool MatchPrefix(std::string_view path, const std::vector<std::string>& prefixes);
    static bool MatchSubstring(std::string_view path, const std::vector<std::string>& substrs);
};

} // namespace har
