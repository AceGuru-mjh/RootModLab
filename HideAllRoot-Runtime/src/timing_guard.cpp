#include "include/timing_guard.h"
#include "include/logging.h"

#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>

namespace har {

long TimingGuard::g_baseline_ns = 0;
long TimingGuard::g_handler_overhead = 0;

static inline long GetTimeNs() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return ts.tv_sec * 1000000000L + ts.tv_nsec;
}

void TimingGuard::Init() {
    // 测量基准：执行 1000 次 getpid()（最简单的 syscall）
    // 取中位数作为基准延迟
    constexpr int ITERATIONS = 1000;
    long samples[ITERATIONS];

    for (int i = 0; i < ITERATIONS; i++) {
        long start = GetTimeNs();
        syscall(__NR_getpid);
        long end = GetTimeNs();
        samples[i] = end - start;
    }

    // 排序取中位数
    // 简单插入排序（1000 个元素足够快）
    for (int i = 1; i < ITERATIONS; i++) {
        long key = samples[i];
        int j = i - 1;
        while (j >= 0 && samples[j] > key) {
            samples[j + 1] = samples[j];
            j--;
        }
        samples[j + 1] = key;
    }

    g_baseline_ns = samples[ITERATIONS / 2];

    // 测量 handler 开销：执行一次被拦截的 syscall 并计时
    // （此时 seccomp 已安装）
    long start = GetTimeNs();
    // 触发一个会被拦截但快速放行的 syscall
    syscall(__NR_getpid);  // getpid 不在拦截列表中，作为对照
    long end = GetTimeNs();
    long unintercepted = end - start;

    // handler 开销 ≈ 被拦截 syscall 耗时 - 未拦截 syscall 耗时
    // 这个值在运行时动态调整
    g_handler_overhead = 0;  // 初始为 0，运行时自适应

    LOG_I("TimingGuard: baseline=%ldns, unintercepted=%ldns",
          g_baseline_ns, unintercepted);
}

void TimingGuard::Normalize(int syscall_nr, bool was_blocked) {
    // 策略：对于快速返回的拦截（如 ENOENT），添加微小延迟
    // 使得总耗时接近正常 syscall 的耗时
    //
    // 正常 openat 耗时：~1-5μs（取决于文件系统）
    // 被拦截 openat 耗时：~0.5-1μs（handler 开销，无实际 I/O）
    // 差异：~0.5-4μs
    //
    // Momo/Launch 的检测阈值：通常 > 10μs 差异才报警
    // 所以大多数情况下不需要额外延迟
    //
    // 但为了安全，对 ENOENT 返回添加 ~500ns 延迟

    if (was_blocked) {
        // 使用 DMB 指令消耗时间（不可被编译器优化）
        // 每次 DMB 约 10-50ns（取决于 CPU）
        volatile int dummy = 0;
        for (int i = 0; i < 20; i++) {
#if defined(__aarch64__) || defined(__arm__)
            asm volatile("dmb ish" ::: "memory");
#else
            asm volatile("" ::: "memory");
#endif
            dummy += i;
        }
        (void)dummy;
    }
}

long TimingGuard::GetBaselineNs() {
    return g_baseline_ns;
}

} // namespace har
