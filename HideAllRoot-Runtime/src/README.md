# HideAllRoot-Runtime/src —— 实验性重写（**未接入构建**）

> ⚠️ **本目录是用户交付的 seccomp-bpf 引擎重写草稿，目前只是落盘存档，NOT wired into the shipping module。**
> 顶层的 `build.sh` 仍然编译 `jni/`（ndk-build → `libzygisk.so`），**不会**编译 `src/`。
> 在以下致命问题修复前，不要把它接入发布构建，否则会让目标 App 崩溃。

## 落盘状态
- 17 个文件已按交付内容写入（CMakeLists + 8 .cpp + 8 .h + zygisk.hpp 占位符）。
- `src/include/zygisk.hpp` 是占位符，需从 Magisk/KernelSU 仓库下载真实头文件才能编译。

## 已知致命问题（待修复后才能接入）
1. **seccomp `SECCOMP_RET_TRAP` + handler 内 `raw_syscall` 重放 = 无限递归崩溃。**
   BPF 对 openat/read/close/getdents64/kill/ptrace 返回 RET_TRAP；SIGSYS handler 内又用
   `raw_syscallN(...)` 重放同一个 syscall。该 `svc #0` 会再次被同一 BPF 过滤 → 再次 RET_TRAP →
   再次进入 handler（线程局部 `g_in_handler` 已为 true，递归分支仍调用 raw_syscall → 再次 trap）。
   每次递归消耗信号帧+栈，最终栈溢出 SIGSEGV。**任何触发这些 syscall 的 App 都会崩。**
   - 注：`open` 未被拦截，故 `HandleOpenat` 若改用 `__NR_open` 重放可不自陷；但 read/close/getdents64/kill/ptrace
     无等价未拦截 syscall，重放必然自陷。
2. **对全部目标 App 的 read/close/getdents64/kill 做 TRAP 过于激进**：性能与稳定性不可接受，
   App 基本不可用（这正是之前评审已标记的“read/close TRAP = app unusable”）。
3. **在 `preServerSpecialize` 给 Zygote/server 进程安装同一套严格 filter**：会破坏 system_server/zygote 自身。
4. **`linker_cleaner.cpp` 的 soinfo 偏移是“推理值”（代码注释自承未经设备验证）**，且手工摘除 solist 节点 +
   `munmap` 非执行段极易在真实设备崩溃；同时它读 `/proc/self/maps`，而该 reads 已被 seccomp TRAP 并过滤，
   导致它看不到要清洗的库（自相矛盾）。
5. **与现有 `jni/main.cpp` 入口冲突**：两者都注册 Zygisk 模块，真要切换必须删除/停用 `jni/`。
6. **产物命名不被 Magisk 加载**：CMakeLists 产出 `libhar_runtime.so`，但 Magisk Zygisk 加载器只加载
   `zygisk/<abi>/libzygisk.so`（文件名必须恰好是 `libzygisk.so`）。需改名或改 soname。
7. **`timing_guard.cpp` 实际是空操作**（仅 20 次 `dmb`，未真正归一化到基线）。

## 建议的安全接入路径
- 保留现有 `jni/` PLT-hook 引擎（已验证可用）作为主隐藏层；
- seccomp 仅作为**“拒绝型”(RET_ERRNO) 微型集**使用：例如对 `ptrace(ATTACH/SEIZE)` 直接返回 EPERM（无需重放，
  不构成递归）；不要做基于路径重放的 openat/read 过滤——路径隐藏留在 PLT hook 层；
- 如需实验 `src/`，请单独建分支/目录，禁止并入发布 zip。
