#pragma once

namespace har {

// ═══════════════════════════════════════════════════════════
// 时序防护：消除 seccomp handler 引入的时序侧信道
// ═══════════════════════════════════════════════════════════

class TimingGuard {
public:
    // 初始化（测量基准延迟）
    static void Init();

    // 在 SIGSYS handler 中调用：归一化处理时间
    // 使得"被拦截"和"未被拦截"的 syscall 耗时差异 < 检测阈值
    static void Normalize(int syscall_nr, bool was_blocked);

    // 获取基准延迟（纳秒）
    static long GetBaselineNs();

private:
    static long g_baseline_ns;      // 无 hook 时的 syscall 基准延迟
    static long g_handler_overhead; // handler 自身开销
};

} // namespace har
