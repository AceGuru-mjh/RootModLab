#pragma once

namespace har {

// ═══════════════════════════════════════════════════════════
// 进程隐藏器：隐藏 root 相关进程
// 配合 seccomp 的 kill/getdents64 拦截使用
// ═══════════════════════════════════════════════════════════

class ProcHider {
public:
    // 初始化：扫描当前进程列表，建立隐藏 PID 集合
    static void Init();

    // 刷新隐藏 PID 集合（定期调用，因为 PID 会变化）
    static void Refresh();

    // 判断 PID 是否应被隐藏
    static bool IsHiddenPid(int pid);

    // 判断进程名是否应被隐藏
    static bool IsHiddenComm(const char* comm);

    // 获取 /proc/<pid>/comm 的内容（缓存）
    static const char* GetCachedComm(int pid);

private:
    static void ScanProc();

    // PID → comm 缓存
    static constexpr int MAX_CACHED_PIDS = 1024;
    struct PidEntry {
        int pid;
        char comm[64];
        bool hidden;
    };
    static PidEntry g_cache[MAX_CACHED_PIDS];
    static int g_cache_count;
};

} // namespace har
