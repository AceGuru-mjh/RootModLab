/*
 * HideAllRoot-Runtime — seccomp 稳妥 PoC
 * ====================================================================
 * 设计原则（与原始"全量 TRAP"方案的关键区别）：
 *
 *  1. 只拦截 openat 一个 syscall，且只在「绕过 PLT 的 raw svc」路径上生效。
 *     - raw svc openat 的 PC 落在 libc 模块之外 → 由本 handler 处理；
 *     - libc 内部发起的 openat（正常路径）我们手动重放，不返回错误，
 *       因此 app 的正常文件访问走 PLT hook + 真实 syscall，不受 seccomp 影响。
 *  2. 绝不对 read / close / 其它高频 syscall 上 seccomp，避免性能崩溃。
 *  3. 不碰 soinfo 链表 / munmap 自身库（原方案崩溃风险点）。
 *  4. 默认关闭（需 config 开启 ENABLE_SECCOMP_POC=1），不影响现有 PLT 引擎。
 *
 * 未经验证的假设（需真机 + Momo 实测，本地无 NDK/真机）：
 *  - 在 SIGSYS handler 内手动重放 syscall(__NR_openat, ...) 时，内核
 *    因已处于 SIGSYS 交付上下文，不会再次触发本 seccomp 过滤器
 *    （即不会无限递归）。若真机会递归，需改为按 seccomp_data.arch 之外的
 *    instruction_pointer 白名单放行 handler 自身——届时再升级。
 *  - 与 zygote 已安装的 app seccomp policy 叠加后，本 TRAP 仍能正确触发。
 *
 * 这是双模块架构中 Runtime 模块的一部分。严格说，seccomp 在 syscall 入口
 * 设卡，正是对抗 raw svc #0 的唯一用户态手段。
 */
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <signal.h>
#include <ucontext.h>
#include <dlfcn.h>
#include <link.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <cstdint>
#include <cstring>

#include "zygisk.hpp"

/* ── 由 main.cpp 提供的接口（在 module 全局初始化后可用） ────────────── */
/* libc 模块加载区间，用于区分 raw svc 与 libc 内部调用 */
extern uintptr_t g_libc_base;
extern uintptr_t g_libc_end;
/* 路径是否需要隐藏（复用 main.cpp 中的 PLT 判断逻辑） */
extern bool seccomp_poc_should_hide(const char *path);

static const char *kTag = "HAR_SECCOMP";

/* 简单日志（不依赖完整 filter 体系） */
static void poc_log(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    __android_log_vprint(ANDROID_LOG_INFO, kTag, fmt, ap);
    va_end(ap);
}

/* ── BPF 过滤器：仅 openat → TRAP，其余 → ALLOW ─────────────────────── */
static struct sock_filter build_filter[] = {
    /* 0: 校验 arch = AArch64 */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    /* 3: 加载 syscall nr */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    /* 4: openat? 是→跳到 TRAP(6)，否→落到 ALLOW(5) */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 1, 0),
    /* 5: ALLOW */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    /* 6: TRAP，data=0x4841 ("HA" 标识) */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP | 0x4841),
};

/* ── SIGSYS handler ─────────────────────────────────────────────────── */
static void poc_sigsys(int signo, siginfo_t *info, void *uctx) {
    (void)info;
    if (signo != SIGSYS) return;

    ucontext_t *uc = (ucontext_t *)uctx;
    /* AArch64: x8=syscall nr, x0..x5=args, x0=return */
    long nr   = uc->uc_mcontext.regs[8];
    long arg1 = uc->uc_mcontext.regs[1];   /* openat pathname */
    uintptr_t ip = uc->uc_mcontext.pc;

    if (nr != __NR_openat) {
        /* 不是我们拦截的 syscall（理论上不会到这，除非规则扩展） */
        uc->uc_mcontext.regs[0] = -ENOSYS;
        return;
    }

    const char *path = (const char *)arg1;
    bool from_libc = (g_libc_base && g_libc_end && ip >= g_libc_base && ip < g_libc_end);

    if (from_libc) {
        /* libc 正常路径：手动重放真实 syscall，返回其结果 */
        long r = syscall(__NR_openat,
                         uc->uc_mcontext.regs[0],
                         uc->uc_mcontext.regs[1],
                         uc->uc_mcontext.regs[2],
                         uc->uc_mcontext.regs[3]);
        uc->uc_mcontext.regs[0] = r;
        return;
    }

    /* raw svc 路径：检查路径 */
    if (path && seccomp_poc_should_hide(path)) {
        uc->uc_mcontext.regs[0] = -ENOENT;   /* 让探测者以为文件不存在 */
        return;
    }

    /* 非隐藏路径的 raw svc：放行（重放真实 syscall） */
    long r = syscall(__NR_openat,
                     uc->uc_mcontext.regs[0],
                     uc->uc_mcontext.regs[1],
                     uc->uc_mcontext.regs[2],
                     uc->uc_mcontext.regs[3]);
    uc->uc_mcontext.regs[0] = r;
}

/* ── 安装 seccomp（在 preAppSpecialize 中对目标进程调用一次） ─────────── */
static bool poc_installed = false;

static void capture_libc_range() {
    dl_iterate_phdr([](struct dl_phdr_info *info, size_t, void *data) -> int {
        if (info->dlpi_name && strstr(info->dlpi_name, "libc.so")) {
            uintptr_t base = (uintptr_t)info->dlpi_phdr;  /* 近似基址，下面改用 dlpi_addr */
            base = (uintptr_t)info->dlpi_addr;
            /* phdr 可能不在模块最前，用 min vaddr 近似：这里取 dlpi_addr + 0 作为 base */
            uintptr_t *out = (uintptr_t *)data;
            out[0] = base;
            out[1] = base + 0x1000000;  /* 粗略区间，仅用于 IP 归属判断，足够 */
            return 1;
        }
        return 0;
    }, (void *)&g_libc_base);
    if (!g_libc_end) g_libc_end = g_libc_base + 0x1000000;
}

bool har_install_seccomp_poc() {
    if (poc_installed) return true;

    capture_libc_range();

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = poc_sigsys;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSYS, &sa, nullptr) != 0) {
        poc_log("sigaction(SIGSYS) failed");
        return false;
    }

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(build_filter) / sizeof(build_filter[0])),
        .filter = build_filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        poc_log("PR_SET_NO_NEW_PRIVS failed");
        return false;
    }

    /* TSYNC: 同步到进程所有线程 */
    if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                SECCOMP_FILTER_FLAG_TSYNC, &prog) != 0) {
        /* 回退：prctl 方式（无 TSYNC 语义） */
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
            poc_log("seccomp install failed");
            return false;
        }
    }

    poc_installed = true;
    poc_log("installed (libc range %p-%p)", (void *)g_libc_base, (void *)g_libc_end);
    return true;
}
