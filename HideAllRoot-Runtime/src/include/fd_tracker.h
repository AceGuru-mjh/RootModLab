#pragma once

#include <unordered_map>
#include <string>
#include <mutex>

namespace har {

// ═══════════════════════════════════════════════════════════
// FD 追踪器：记录 openat 返回的 fd 对应的路径
// 用于后续 read/pread 时判断是否需要过滤内容
// ═══════════════════════════════════════════════════════════

class FdTracker {
public:
    // 记录 fd → path 映射
    static void Track(int fd, const char* path);

    // 移除追踪（close 时调用）
    static void Untrack(int fd);

    // 查询 fd 是否指向需要过滤内容的文件
    static bool IsContentFilterable(int fd);

    // 获取 fd 对应的路径
    static const char* GetPath(int fd);

    // 获取 fd 的过滤类型
    enum class FilterType {
        NONE,           // 不需要过滤
        MAPS,           // /proc/self/maps, /proc/<pid>/maps
        MOUNTS,         // /proc/mounts, /proc/self/mountinfo
        MODULES,        // /proc/modules
        ENVIRON,        // /proc/self/environ
        STATUS,         // /proc/self/status (TracerPid)
        CMDLINE,        // /proc/<pid>/cmdline
        NET_UNIX,       // /proc/net/unix
        PACKAGES,       // /data/system/packages.xml
        BUILD_PROP,     // /system/build.prop
        SELINUX_ATTR,   // /proc/self/attr/current
        PROC_DIR,       // /proc 目录（getdents64）
    };

    static FilterType GetFilterType(int fd);

    // 清空所有追踪（进程退出时）
    static void Clear();

private:
    struct FdEntry {
        std::string path;
        FilterType type;
    };

    static std::unordered_map<int, FdEntry> g_map;
    static std::mutex g_mutex;

    static FilterType ClassifyPath(const char* path);
};

} // namespace har
