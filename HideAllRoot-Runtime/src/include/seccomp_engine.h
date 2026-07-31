#pragma once

#include <cstdint>

namespace har {

// ═══════════════════════════════════════════════════════════
// Seccomp 引擎：BPF 过滤器 + SIGSYS handler
// 替代 PLT Hook，拦截所有 syscall（包括 raw svc #0）
// ═══════════════════════════════════════════════════════════

class SeccompEngine {
public:
    // 安装 seccomp 过滤器和 SIGSYS handler
    // 必须在任何 app 代码执行前调用（preAppSpecialize）
    // 返回 true 表示安装成功
    static bool Install();

    // 是否已安装
    static bool IsInstalled();

    // 获取拦截统计（用于调试）
    struct Stats {
        uint64_t total_intercepted;
        uint64_t total_blocked;
        uint64_t total_allowed;
        uint64_t openat_blocked;
        uint64_t faccessat_blocked;
        uint64_t stat_blocked;
        uint64_t read_filtered;
        uint64_t getdents64_filtered;
        uint64_t readlink_blocked;
        uint64_t kill_blocked;
        uint64_t ptrace_blocked;
    };
    static Stats GetStats();

    // 临时禁用（用于调试或白名单 app）
    static void SetEnabled(bool enabled);
    static bool IsEnabled();

private:
    // BPF 过滤器构建
    static bool BuildAndInstallFilter();

    // SIGSYS handler 安装
    static bool InstallSigsysHandler();

    // 各类 syscall 的处理函数
    static long HandleOpenat(int dirfd, const char* path, int flags, int mode);
    static long HandleFaccessat(int dirfd, const char* path, int mode, int flags);
    static long HandleNewfstatat(int dirfd, const char* path, void* statbuf, int flags);
    static long HandleStatx(int dirfd, const char* path, int flags,
                            unsigned mask, void* statxbuf);
    static long HandleReadlinkat(int dirfd, const char* path, char* buf, size_t bufsiz);
    static long HandleRead(int fd, void* buf, size_t count);
    static long HandlePread64(int fd, void* buf, size_t count, long offset);
    static long HandleGetdents64(int fd, void* buf, size_t count);
    static long HandleKill(int pid, int sig);
    static long HandlePtrace(long request, long pid, void* addr, void* data);
    static long HandleClose(int fd);

    // 内容过滤（read 返回后修改 buffer）
    static long FilterReadContent(int fd, char* buf, long bytes_read);
    static long FilterMapsContent(char* buf, long len);
    static long FilterMountsContent(char* buf, long len);
    static long FilterModulesContent(char* buf, long len);
    static long FilterEnvironContent(char* buf, long len);
    static long FilterStatusContent(char* buf, long len);
    static long FilterNetUnixContent(char* buf, long len);
    static long FilterGetdents64(char* buf, long len);
};

} // namespace har
