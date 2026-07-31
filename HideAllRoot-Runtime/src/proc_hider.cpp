#include "include/proc_hider.h"
#include "include/path_filter.h"
#include "include/logging.h"

#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cstdlib>

namespace har {

ProcHider::PidEntry ProcHider::g_cache[ProcHider::MAX_CACHED_PIDS];
int ProcHider::g_cache_count = 0;

void ProcHider::Init() {
    ScanProc();
    LOG_I("ProcHider: initialized, %d PIDs cached, monitoring", g_cache_count);
}

void ProcHider::Refresh() {
    ScanProc();
}

bool ProcHider::IsHiddenPid(int pid) {
    for (int i = 0; i < g_cache_count; i++) {
        if (g_cache[i].pid == pid) {
            return g_cache[i].hidden;
        }
    }

    // 不在缓存中：实时检查
    char comm_path[64];
    char comm[256];
    snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);

    int fd = open(comm_path, O_RDONLY);
    if (fd < 0) return false;  // 进程不存在

    long n = read(fd, comm, sizeof(comm) - 1);
    close(fd);

    if (n <= 0) return false;
    comm[n] = '\0';
    char* nl = strchr(comm, '\n');
    if (nl) *nl = '\0';

    return PathFilter::ShouldHideProcess(comm);
}

bool ProcHider::IsHiddenComm(const char* comm) {
    return PathFilter::ShouldHideProcess(comm);
}

const char* ProcHider::GetCachedComm(int pid) {
    for (int i = 0; i < g_cache_count; i++) {
        if (g_cache[i].pid == pid) {
            return g_cache[i].comm;
        }
    }
    return nullptr;
}

void ProcHider::ScanProc() {
    g_cache_count = 0;

    DIR* dir = opendir("/proc");
    if (!dir) return;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        // 只处理数字目录（PID）
        bool is_pid = true;
        for (const char* p = entry->d_name; *p; p++) {
            if (*p < '0' || *p > '9') { is_pid = false; break; }
        }
        if (!is_pid) continue;

        int pid = atoi(entry->d_name);
        if (pid <= 0) continue;

        // 读取 comm
        char comm_path[64];
        char comm[256];
        snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);

        int fd = open(comm_path, O_RDONLY);
        if (fd < 0) continue;

        long n = read(fd, comm, sizeof(comm) - 1);
        close(fd);

        if (n <= 0) continue;
        comm[n] = '\0';
        char* nl = strchr(comm, '\n');
        if (nl) *nl = '\0';

        // 存入缓存
        if (g_cache_count < MAX_CACHED_PIDS) {
            auto& e = g_cache[g_cache_count];
            e.pid = pid;
            strncpy(e.comm, comm, sizeof(e.comm) - 1);
            e.comm[sizeof(e.comm) - 1] = '\0';
            e.hidden = PathFilter::ShouldHideProcess(comm);
            g_cache_count++;
        }
    }

    closedir(dir);
}

} // namespace har
