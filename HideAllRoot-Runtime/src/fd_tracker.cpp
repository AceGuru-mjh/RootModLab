#include "include/fd_tracker.h"
#include "include/logging.h"

#include <cstring>
#include <unistd.h>

namespace har {

std::unordered_map<int, FdTracker::FdEntry> FdTracker::g_map;
std::mutex FdTracker::g_mutex;

void FdTracker::Track(int fd, const char* path) {
    if (fd < 0 || !path) return;

    FilterType type = ClassifyPath(path);
    if (type == FilterType::NONE) return;  // 不需要追踪

    std::lock_guard<std::mutex> lock(g_mutex);
    g_map[fd] = FdEntry{path, type};

    LOG_V("FdTracker: fd=%d → %s (type=%d)", fd, path, (int)type);
}

void FdTracker::Untrack(int fd) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_map.erase(fd);
}

bool FdTracker::IsContentFilterable(int fd) {
    std::lock_guard<std::mutex> lock(g_mutex);
    auto it = g_map.find(fd);
    return it != g_map.end() && it->second.type != FilterType::NONE;
}

const char* FdTracker::GetPath(int fd) {
    std::lock_guard<std::mutex> lock(g_mutex);
    auto it = g_map.find(fd);
    return (it != g_map.end()) ? it->second.path.c_str() : nullptr;
}

FdTracker::FilterType FdTracker::GetFilterType(int fd) {
    std::lock_guard<std::mutex> lock(g_mutex);
    auto it = g_map.find(fd);
    return (it != g_map.end()) ? it->second.type : FilterType::NONE;
}

void FdTracker::Clear() {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_map.clear();
}

FdTracker::FilterType FdTracker::ClassifyPath(const char* path) {
    if (!path) return FilterType::NONE;

    // /proc/self/maps 或 /proc/<pid>/maps
    if (strstr(path, "/maps") && strstr(path, "/proc/"))
        return FilterType::MAPS;

    // /proc/mounts, /proc/self/mountinfo, /proc/self/mounts
    if (strstr(path, "mount") && strstr(path, "/proc/"))
        return FilterType::MOUNTS;

    // /proc/modules
    if (strcmp(path, "/proc/modules") == 0)
        return FilterType::MODULES;

    // /proc/self/environ 或 /proc/<pid>/environ
    if (strstr(path, "/environ") && strstr(path, "/proc/"))
        return FilterType::ENVIRON;

    // /proc/self/status（TracerPid 字段）
    if (strstr(path, "/status") && strstr(path, "/proc/"))
        return FilterType::STATUS;

    // /proc/<pid>/cmdline
    if (strstr(path, "/cmdline") && strstr(path, "/proc/"))
        return FilterType::CMDLINE;

    // /proc/net/unix
    if (strcmp(path, "/proc/net/unix") == 0)
        return FilterType::NET_UNIX;

    // /data/system/packages.xml
    if (strstr(path, "packages.xml") || strstr(path, "packages.list"))
        return FilterType::PACKAGES;

    // build.prop
    if (strstr(path, "build.prop"))
        return FilterType::BUILD_PROP;

    // /proc/self/attr/current (SELinux context)
    if (strstr(path, "/attr/current"))
        return FilterType::SELINUX_ATTR;

    // /proc 目录本身（用于 getdents64 过滤）
    if (strcmp(path, "/proc") == 0 || strcmp(path, "/proc/") == 0)
        return FilterType::PROC_DIR;

    return FilterType::NONE;
}

} // namespace har
