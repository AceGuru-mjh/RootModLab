#include "include/seccomp_engine.h"
#include "include/path_filter.h"
#include "include/fd_tracker.h"
#include "include/logging.h"

#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <cstring>
#include <cstdlib>
#include <atomic>
#include <vector>

// ═══════════════════════════════════════════════════════════
// 平台适配
// ═══════════════════════════════════════════════════════════

#if defined(__aarch64__)
    #define REG_SYSCALL_NR  regs[8]
    #define REG_ARG0        regs[0]
    #define REG_ARG1        regs[1]
    #define REG_ARG2        regs[2]
    #define REG_ARG3        regs[3]
    #define REG_ARG4        regs[4]
    #define REG_ARG5        regs[5]
    #define REG_RET         regs[0]
    #define AUDIT_ARCH_CUR  AUDIT_ARCH_AARCH64

    // 原始 syscall（绕过 libc，直接 svc）
    static inline long raw_syscall6(long nr, long a0, long a1, long a2,
                                     long a3, long a4, long a5) {
        register long x8 asm("x8") = nr;
        register long x0 asm("x0") = a0;
        register long x1 asm("x1") = a1;
        register long x2 asm("x2") = a2;
        register long x3 asm("x3") = a3;
        register long x4 asm("x4") = a4;
        register long x5 asm("x5") = a5;
        asm volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                     : "memory", "cc");
        return x0;
    }

#elif defined(__arm__)
    #define REG_SYSCALL_NR  arm_r7
    #define REG_ARG0        arm_r0
    #define REG_ARG1        arm_r1
    #define REG_ARG2        arm_r2
    #define REG_ARG3        arm_r3
    #define REG_ARG4        arm_r4
    #define REG_ARG5        arm_r5
    #define REG_RET         arm_r0
    #define AUDIT_ARCH_CUR  AUDIT_ARCH_ARM

    static inline long raw_syscall6(long nr, long a0, long a1, long a2,
                                     long a3, long a4, long a5) {
        register long r7 asm("r7") = nr;
        register long r0 asm("r0") = a0;
        register long r1 asm("r1") = a1;
        register long r2 asm("r2") = a2;
        register long r3 asm("r3") = a3;
        register long r4 asm("r4") = a4;
        register long r5 asm("r5") = a5;
        asm volatile("svc #0"
                     : "+r"(r0)
                     : "r"(r7), "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5)
                     : "memory", "cc");
        return r0;
    }
#else
    #error "Unsupported architecture"
#endif

// 简化版 raw syscall
static inline long raw_syscall4(long nr, long a0, long a1, long a2, long a3) {
    return raw_syscall6(nr, a0, a1, a2, a3, 0, 0);
}
static inline long raw_syscall3(long nr, long a0, long a1, long a2) {
    return raw_syscall6(nr, a0, a1, a2, 0, 0, 0);
}
static inline long raw_syscall2(long nr, long a0, long a1) {
    return raw_syscall6(nr, a0, a1, 0, 0, 0, 0);
}
static inline long raw_syscall1(long nr, long a0) {
    return raw_syscall6(nr, a0, 0, 0, 0, 0, 0);
}

namespace har {

// ═══════════════════════════════════════════════════════════
// 全局状态
// ═══════════════════════════════════════════════════════════

static std::atomic<bool> g_installed{false};
static std::atomic<bool> g_enabled{true};
static struct sigaction g_old_sigsys;
static SeccompEngine::Stats g_stats{};

// 线程局部：防止 SIGSYS handler 中递归
static thread_local bool g_in_handler = false;

// ═══════════════════════════════════════════════════════════
// SIGSYS Handler（核心）
// ═══════════════════════════════════════════════════════════

static void SigsysHandler(int signo, siginfo_t* info, void* ucontext) {
    if (signo != SIGSYS) return;

    // 防止递归（handler 内部的 syscall 也可能触发 seccomp）
    if (g_in_handler) {
        // 递归情况：直接执行原始 syscall
        ucontext_t* ctx = (ucontext_t*)ucontext;
        long nr = ctx->uc_mcontext.REG_SYSCALL_NR;
        long a0 = ctx->uc_mcontext.REG_ARG0;
        long a1 = ctx->uc_mcontext.REG_ARG1;
        long a2 = ctx->uc_mcontext.REG_ARG2;
        long a3 = ctx->uc_mcontext.REG_ARG3;
        long a4 = ctx->uc_mcontext.REG_ARG4;
        long a5 = ctx->uc_mcontext.REG_ARG5;
        ctx->uc_mcontext.REG_RET = raw_syscall6(nr, a0, a1, a2, a3, a4, a5);
        return;
    }

    g_in_handler = true;

    ucontext_t* ctx = (ucontext_t*)ucontext;
    long nr = ctx->uc_mcontext.REG_SYSCALL_NR;
    long a0 = ctx->uc_mcontext.REG_ARG0;
    long a1 = ctx->uc_mcontext.REG_ARG1;
    long a2 = ctx->uc_mcontext.REG_ARG2;
    long a3 = ctx->uc_mcontext.REG_ARG3;
    long a4 = ctx->uc_mcontext.REG_ARG4;
    long a5 = ctx->uc_mcontext.REG_ARG5;

    long result;
    bool handled = false;

    if (!g_enabled.load(std::memory_order_relaxed)) {
        // 禁用状态：直接执行原始 syscall
        result = raw_syscall6(nr, a0, a1, a2, a3, a4, a5);
        handled = true;
    } else {
        switch (nr) {

        case __NR_openat:
            result = SeccompEngine::HandleOpenat(
                (int)a0, (const char*)a1, (int)a2, (int)a3);
            handled = true;
            break;

        case __NR_faccessat:
            result = SeccompEngine::HandleFaccessat(
                (int)a0, (const char*)a1, (int)a2, 0);
            handled = true;
            break;

#ifdef __NR_faccessat2
        case __NR_faccessat2:
            result = SeccompEngine::HandleFaccessat(
                (int)a0, (const char*)a1, (int)a2, (int)a3);
            handled = true;
            break;
#endif

        case __NR_newfstatat:
            result = SeccompEngine::HandleNewfstatat(
                (int)a0, (const char*)a1, (void*)a2, (int)a3);
            handled = true;
            break;

#ifdef __NR_statx
        case __NR_statx:
            result = SeccompEngine::HandleStatx(
                (int)a0, (const char*)a1, (int)a2, (unsigned)a3, (void*)a4);
            handled = true;
            break;
#endif

        case __NR_readlinkat:
            result = SeccompEngine::HandleReadlinkat(
                (int)a0, (const char*)a1, (char*)a2, (size_t)a3);
            handled = true;
            break;

        case __NR_read:
            result = SeccompEngine::HandleRead((int)a0, (void*)a1, (size_t)a2);
            handled = true;
            break;

        case __NR_pread64:
            result = SeccompEngine::HandlePread64(
                (int)a0, (void*)a1, (size_t)a2, (long)a3);
            handled = true;
            break;

        case __NR_getdents64:
            result = SeccompEngine::HandleGetdents64((int)a0, (void*)a1, (size_t)a2);
            handled = true;
            break;

        case __NR_kill:
            result = SeccompEngine::HandleKill((int)a0, (int)a1);
            handled = true;
            break;

        case __NR_ptrace:
            result = SeccompEngine::HandlePtrace(a0, a1, (void*)a2, (void*)a3);
            handled = true;
            break;

        case __NR_close:
            result = SeccompEngine::HandleClose((int)a0);
            handled = true;
            break;

        default:
            // 不在处理列表中：直接执行
            result = raw_syscall6(nr, a0, a1, a2, a3, a4, a5);
            handled = true;
            break;
        }
    }

    ctx->uc_mcontext.REG_RET = result;
    g_in_handler = false;
}

// ═══════════════════════════════════════════════════════════
// 安装
// ═══════════════════════════════════════════════════════════

bool SeccompEngine::Install() {
    if (g_installed.load()) {
        LOG_W("SeccompEngine: already installed");
        return true;
    }

    if (!InstallSigsysHandler()) {
        LOG_E("SeccompEngine: failed to install SIGSYS handler");
        return false;
    }

    if (!BuildAndInstallFilter()) {
        LOG_E("SeccompEngine: failed to install BPF filter");
        return false;
    }

    g_installed.store(true);
    LOG_I("SeccompEngine: installed successfully (pid=%d)", getpid());
    return true;
}

bool SeccompEngine::IsInstalled() {
    return g_installed.load();
}

void SeccompEngine::SetEnabled(bool enabled) {
    g_enabled.store(enabled, std::memory_order_relaxed);
}

bool SeccompEngine::IsEnabled() {
    return g_enabled.load(std::memory_order_relaxed);
}

SeccompEngine::Stats SeccompEngine::GetStats() {
    return g_stats;
}

// ═══════════════════════════════════════════════════════════
// SIGSYS Handler 安装
// ═══════════════════════════════════════════════════════════

bool SeccompEngine::InstallSigsysHandler() {
    struct sigaction sa{};
    sa.sa_sigaction = SigsysHandler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART | SA_NODEFER;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGSYS, &sa, &g_old_sigsys) != 0) {
        LOG_E("SeccompEngine: sigaction(SIGSYS) failed: %s", strerror(errno));
        return false;
    }

    return true;
}

// ═══════════════════════════════════════════════════════════
// BPF 过滤器构建与安装
// ═══════════════════════════════════════════════════════════

bool SeccompEngine::BuildAndInstallFilter() {
    // 需要拦截的 syscall 号列表
    static const uint32_t kIntercepted[] = {
        __NR_openat,
        __NR_faccessat,
#ifdef __NR_faccessat2
        __NR_faccessat2,
#endif
        __NR_newfstatat,
#ifdef __NR_statx
        __NR_statx,
#endif
        __NR_readlinkat,
        __NR_read,
        __NR_pread64,
        __NR_getdents64,
        __NR_kill,
        __NR_ptrace,
        __NR_close,
    };

    const int count = sizeof(kIntercepted) / sizeof(kIntercepted[0]);

    // 构建 BPF 程序
    // 结构：
    //   [0]  LD arch
    //   [1]  JEQ AARCH64 ? continue : ALLOW
    //   [2]  ALLOW (wrong arch)
    //   [3]  LD syscall nr
    //   [4..4+count-1]  JEQ intercepted[i] ? TRAP : next
    //   [4+count]  ALLOW (default)
    //   [4+count+1]  TRAP

    std::vector<struct sock_filter> filter;
    filter.reserve(4 + count + 2);

    // 验证架构
    filter.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
        (uint32_t)offsetof(struct seccomp_data, arch)));
    filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
        AUDIT_ARCH_CUR, 1, 0));
    filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    // 加载 syscall 号
    filter.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
        (uint32_t)offsetof(struct seccomp_data, nr)));

    // 对每个拦截目标：匹配则跳到 TRAP
    for (int i = 0; i < count; i++) {
        int jt = count - i;  // 跳到 TRAP（相对于下一条指令的偏移）
        filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
            kIntercepted[i], jt, 0));
    }

    // 默认：ALLOW
    filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    // TRAP：发送 SIGSYS（带自定义 si_code 标识）
    filter.push_back(BPF_STMT(BPF_RET | BPF_K,
        SECCOMP_RET_TRAP | 0x4841));  // "HA" = HideAllRoot

    // 安装
    struct sock_fprog prog{};
    prog.len = (unsigned short)filter.size();
    prog.filter = filter.data();

    // 设置 no_new_privs（seccomp 前置要求）
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        LOG_E("SeccompEngine: PR_SET_NO_NEW_PRIVS failed: %s", strerror(errno));
        return false;
    }

    // 优先使用 seccomp() syscall（支持更多 flag）
    long ret = raw_syscall3(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                            SECCOMP_FILTER_FLAG_TSYNC, (long)&prog);
    if (ret != 0) {
        // 回退到 prctl
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
            LOG_E("SeccompEngine: filter install failed: %s", strerror(errno));
            return false;
        }
    }

    LOG_I("SeccompEngine: BPF filter installed (%zu instructions, %d syscalls)",
          filter.size(), count);
    return true;
}

// ═══════════════════════════════════════════════════════════
// Syscall 处理函数
// ═══════════════════════════════════════════════════════════

long SeccompEngine::HandleOpenat(int dirfd, const char* path,
                                  int flags, int mode) {
    g_stats.total_intercepted++;

    if (path && PathFilter::ShouldHidePath(path)) {
        g_stats.total_blocked++;
        g_stats.openat_blocked++;
        LOG_V("SeccompEngine: BLOCK openat(%s)", path);
        errno = ENOENT;
        return -ENOENT;
    }

    // 放行：执行原始 syscall
    long ret = raw_syscall4(__NR_openat, dirfd, (long)path, flags, mode);

    // 追踪返回的 fd
    if (ret >= 0 && path) {
        FdTracker::Track((int)ret, path);
    }

    g_stats.total_allowed++;
    return ret;
}

long SeccompEngine::HandleFaccessat(int dirfd, const char* path,
                                     int mode, int flags) {
    g_stats.total_intercepted++;

    if (path && PathFilter::ShouldHidePath(path)) {
        g_stats.total_blocked++;
        g_stats.faccessat_blocked++;
        LOG_V("SeccompEngine: BLOCK faccessat(%s)", path);
        errno = ENOENT;
        return -ENOENT;
    }

    long ret;
#ifdef __NR_faccessat2
    if (flags != 0) {
        ret = raw_syscall4(__NR_faccessat2, dirfd, (long)path, mode, flags);
    } else
#endif
    {
        ret = raw_syscall3(__NR_faccessat, dirfd, (long)path, mode);
    }

    g_stats.total_allowed++;
    return ret;
}

long SeccompEngine::HandleNewfstatat(int dirfd, const char* path,
                                      void* statbuf, int flags) {
    g_stats.total_intercepted++;

    if (path && PathFilter::ShouldHidePath(path)) {
        g_stats.total_blocked++;
        g_stats.stat_blocked++;
        LOG_V("SeccompEngine: BLOCK newfstatat(%s)", path);
        errno = ENOENT;
        return -ENOENT;
    }

    long ret = raw_syscall4(__NR_newfstatat, dirfd, (long)path,
                            (long)statbuf, flags);
    g_stats.total_allowed++;
    return ret;
}

long SeccompEngine::HandleStatx(int dirfd, const char* path, int flags,
                                 unsigned mask, void* statxbuf) {
    g_stats.total_intercepted++;

    if (path && PathFilter::ShouldHidePath(path)) {
        g_stats.total_blocked++;
        g_stats.stat_blocked++;
        LOG_V("SeccompEngine: BLOCK statx(%s)", path);
        errno = ENOENT;
        return -ENOENT;
    }

#ifdef __NR_statx
    long ret = raw_syscall6(__NR_statx, dirfd, (long)path, flags,
                            mask, (long)statxbuf, 0);
#else
    long ret = -ENOSYS;
#endif
    g_stats.total_allowed++;
    return ret;
}

long SeccompEngine::HandleReadlinkat(int dirfd, const char* path,
                                      char* buf, size_t bufsiz) {
    g_stats.total_intercepted++;

    // 先执行原始 readlinkat
    long ret = raw_syscall4(__NR_readlinkat, dirfd, (long)path,
                            (long)buf, (long)bufsiz);
    if (ret <= 0) {
        g_stats.total_allowed++;
        return ret;
    }

    // 检查链接目标是否需要隐藏
    // 临时 null-terminate（readlinkat 不保证）
    char saved = (ret < (long)bufsiz) ? buf[ret] : '\0';
    if (ret < (long)bufsiz) buf[ret] = '\0';

    if (PathFilter::ShouldHideLink(path, buf)) {
        g_stats.total_blocked++;
        g_stats.readlink_blocked++;
        LOG_V("SeccompEngine: BLOCK readlinkat(%s) → %s", path, buf);
        errno = ENOENT;
        return -ENOENT;
    }

    // 恢复
    if (ret < (long)bufsiz) buf[ret] = saved;

    g_stats.total_allowed++;
    return ret;
}

long SeccompEngine::HandleRead(int fd, void* buf, size_t count) {
    g_stats.total_intercepted++;

    // 先执行原始 read
    long ret = raw_syscall3(__NR_read, fd, (long)buf, (long)count);
    if (ret <= 0) {
        g_stats.total_allowed++;
        return ret;
    }

    // 检查是否需要过滤内容
    if (FdTracker::IsContentFilterable(fd)) {
        long filtered = FilterReadContent(fd, (char*)buf, ret);
        if (filtered != ret) {
            g_stats.read_filtered++;
            return filtered;
        }
    }

    g_stats.total_allowed++;
    return ret;
}

long SeccompEngine::HandlePread64(int fd, void* buf, size_t count, long offset) {
    g_stats.total_intercepted++;

    long ret = raw_syscall4(__NR_pread64, fd, (long)buf, (long)count, offset);
    if (ret <= 0) {
        g_stats.total_allowed++;
        return ret;
    }

    if (FdTracker::IsContentFilterable(fd)) {
        long filtered = FilterReadContent(fd, (char*)buf, ret);
        if (filtered != ret) {
            g_stats.read_filtered++;
            return filtered;
        }
    }

    g_stats.total_allowed++;
    return ret;
}

long SeccompEngine::HandleGetdents64(int fd, void* buf, size_t count) {
    g_stats.total_intercepted++;

    // 先执行原始 getdents64
    long ret = raw_syscall3(__NR_getdents64, fd, (long)buf, (long)count);
    if (ret <= 0) {
        g_stats.total_allowed++;
        return ret;
    }

    // 检查 fd 是否指向需要过滤的目录
    if (FdTracker::GetFilterType(fd) == FdTracker::FilterType::PROC_DIR) {
        long filtered = FilterGetdents64((char*)buf, ret);
        if (filtered != ret) {
            g_stats.getdents64_filtered++;
            return filtered;
        }
    }

    g_stats.total_allowed++;
    return ret;
}

long SeccompEngine::HandleKill(int pid, int sig) {
    g_stats.total_intercepted++;

    // 检查目标 PID 是否是被隐藏的进程
    // 通过 /proc/<pid>/comm 判断
    if (pid > 0) {
        char comm_path[64];
        char comm[256];
        snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);

        // 用 raw syscall 读取（避免递归）
        int fd = (int)raw_syscall4(__NR_openat, AT_FDCWD,
                                    (long)comm_path, O_RDONLY, 0);
        if (fd >= 0) {
            long n = raw_syscall3(__NR_read, fd, (long)comm, sizeof(comm) - 1);
            raw_syscall1(__NR_close, fd);

            if (n > 0) {
                comm[n] = '\0';
                // 去除换行
                char* nl = strchr(comm, '\n');
                if (nl) *nl = '\0';

                if (PathFilter::ShouldHideProcess(comm)) {
                    g_stats.total_blocked++;
                    g_stats.kill_blocked++;
                    LOG_V("SeccompEngine: BLOCK kill(%d) [%s]", pid, comm);
                    errno = ESRCH;
                    return -ESRCH;
                }
            }
        }
    }

    long ret = raw_syscall2(__NR_kill, pid, sig);
    g_stats.total_allowed++;
    return ret;
}

long SeccompEngine::HandlePtrace(long request, long pid,
                                  void* addr, void* data) {
    g_stats.total_intercepted++;

    // 阻止对自身的 ptrace attach（反调试）
    if (request == 16 /*PTRACE_ATTACH*/ || request == 0x4206 /*PTRACE_SEIZE*/) {
        g_stats.total_blocked++;
        g_stats.ptrace_blocked++;
        LOG_V("SeccompEngine: BLOCK ptrace(attach, %ld)", pid);
        errno = EPERM;
        return -EPERM;
    }

    long ret = raw_syscall4(__NR_ptrace, request, pid, (long)addr, (long)data);
    g_stats.total_allowed++;
    return ret;
}

long SeccompEngine::HandleClose(int fd) {
    g_stats.total_intercepted++;

    // 取消 fd 追踪
    FdTracker::Untrack(fd);

    long ret = raw_syscall1(__NR_close, fd);
    g_stats.total_allowed++;
    return ret;
}

// ═══════════════════════════════════════════════════════════
// 内容过滤
// ═══════════════════════════════════════════════════════════

long SeccompEngine::FilterReadContent(int fd, char* buf, long bytes_read) {
    auto type = FdTracker::GetFilterType(fd);

    switch (type) {
    case FdTracker::FilterType::MAPS:
        return FilterMapsContent(buf, bytes_read);
    case FdTracker::FilterType::MOUNTS:
        return FilterMountsContent(buf, bytes_read);
    case FdTracker::FilterType::MODULES:
        return FilterModulesContent(buf, bytes_read);
    case FdTracker::FilterType::ENVIRON:
        return FilterEnvironContent(buf, bytes_read);
    case FdTracker::FilterType::STATUS:
        return FilterStatusContent(buf, bytes_read);
    case FdTracker::FilterType::NET_UNIX:
        return FilterNetUnixContent(buf, bytes_read);
    default:
        return bytes_read;
    }
}

// 通用行过滤：移除匹配的行，压缩 buffer
static long FilterLines(char* buf, long len,
                        bool (*should_remove)(const char*, size_t)) {
    long write_pos = 0;
    long read_pos = 0;

    while (read_pos < len) {
        // 找到行尾
        long line_start = read_pos;
        while (read_pos < len && buf[read_pos] != '\n') {
            read_pos++;
        }
        bool has_newline = (read_pos < len);
        long line_len = read_pos - line_start;
        if (has_newline) read_pos++;  // 跳过 '\n'

        // 判断是否移除
        if (should_remove(buf + line_start, line_len)) {
            continue;  // 跳过此行
        }

        // 保留：复制到 write_pos
        if (write_pos != line_start) {
            memmove(buf + write_pos, buf + line_start, line_len);
        }
        write_pos += line_len;
        if (has_newline) {
            buf[write_pos++] = '\n';
        }
    }

    return write_pos;
}

static bool ShouldRemoveMapsLine(const char* line, size_t len) {
    return PathFilter::ShouldFilterLine(line, len);
}

static bool ShouldRemoveMountLine(const char* line, size_t len) {
    return PathFilter::ShouldFilterMount(line, len);
}

static bool ShouldRemoveModuleLine(const char* line, size_t len) {
    // /proc/modules 格式：name size refcount deps state offset
    // 检查模块名
    return PathFilter::ShouldFilterLine(line, len);
}

static bool ShouldRemoveNetUnixLine(const char* line, size_t len) {
    // /proc/net/unix 中包含 magisk/zygisk socket 路径
    return PathFilter::ShouldFilterLine(line, len);
}

long SeccompEngine::FilterMapsContent(char* buf, long len) {
    return FilterLines(buf, len, ShouldRemoveMapsLine);
}

long SeccompEngine::FilterMountsContent(char* buf, long len) {
    return FilterLines(buf, len, ShouldRemoveMountLine);
}

long SeccompEngine::FilterModulesContent(char* buf, long len) {
    return FilterLines(buf, len, ShouldRemoveModuleLine);
}

long SeccompEngine::FilterNetUnixContent(char* buf, long len) {
    return FilterLines(buf, len, ShouldRemoveNetUnixLine);
}

long SeccompEngine::FilterEnvironContent(char* buf, long len) {
    // environ 是 null-separated，不是 newline-separated
    long write_pos = 0;
    long read_pos = 0;

    while (read_pos < len) {
        long entry_start = read_pos;
        while (read_pos < len && buf[read_pos] != '\0') {
            read_pos++;
        }
        long entry_len = read_pos - entry_start;
        if (read_pos < len) read_pos++;  // 跳过 '\0'

        if (PathFilter::ShouldFilterEnviron(buf + entry_start, entry_len)) {
            continue;
        }

        if (write_pos != entry_start) {
            memmove(buf + write_pos, buf + entry_start, entry_len);
        }
        write_pos += entry_len;
        buf[write_pos++] = '\0';
    }

    return write_pos;
}

long SeccompEngine::FilterStatusContent(char* buf, long len) {
    // /proc/self/status：将 TracerPid 行改为 0
    // 查找 "TracerPid:\t" 前缀
    const char* marker = "TracerPid:";
    char* pos = (char*)memmem(buf, len, marker, strlen(marker));

    if (pos) {
        // 找到冒号后的数字，替换为 0
        char* num_start = pos + strlen(marker);
        while (num_start < buf + len && (*num_start == '\t' || *num_start == ' ')) {
            num_start++;
        }
        // 找到数字结尾
        char* num_end = num_start;
        while (num_end < buf + len && *num_end >= '0' && *num_end <= '9') {
            num_end++;
        }

        // 如果当前值不是 0，替换为 0
        if (num_end > num_start && !(num_end - num_start == 1 && *num_start == '0')) {
            // 用 memmove 压缩
            long tail_len = (buf + len) - num_end;
            *num_start = '0';
            memmove(num_start + 1, num_end, tail_len);
            len -= (num_end - num_start - 1);
        }
    }

    return len;
}

long SeccompEngine::FilterGetdents64(char* buf, long len) {
    // linux_dirent64 结构：
    // struct linux_dirent64 {
    //     uint64_t        d_ino;
    //     int64_t         d_off;
    //     unsigned short  d_reclen;
    //     unsigned char   d_type;
    //     char            d_name[];
    // };

    long write_pos = 0;
    long read_pos = 0;

    while (read_pos < len) {
        struct linux_dirent64* de = (struct linux_dirent64*)(buf + read_pos);
        unsigned short reclen = de->d_reclen;
        if (reclen == 0) break;  // 防止无限循环

        const char* name = de->d_name;

        if (PathFilter::ShouldHideDentry("/proc", name)) {
            LOG_V("SeccompEngine: HIDE dentry /proc/%s", name);
            // 跳过此条目
            read_pos += reclen;
            continue;
        }

        // 保留：复制到 write_pos
        if (write_pos != read_pos) {
            memmove(buf + write_pos, buf + read_pos, reclen);
        }
        write_pos += reclen;
        read_pos += reclen;
    }

    return write_pos;
}

} // namespace har
