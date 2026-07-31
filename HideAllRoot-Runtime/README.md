# HideAllRoot-Runtime

双模块架构之**运行时**模块（`id=hideallroot_runtime`，`zygisk=yes`）。

- Zygisk 注入 `libzygisk.so`，在应用进程内做深度隐藏：
  - PLT hook 引擎：`open/openat/openat2/access/stat/readlink/getdents64` 等拦截、属性过滤、`/proc` 痕迹清理、`ptrace` 反调试。
  - seccomp-bpf 稳妥 PoC（`ENABLE_SECCOMP_POC=0` 默认关）：仅拦截 libc 外的原始 `svc #0` `openat`，经 SIGSYS 处理后返回 `-ENOENT`。
- 依赖 **HideAllRoot-System** 先安装（`customize.sh` 会校验，缺失则中止）。
- 配置：`config/default.conf` → 安装时写入 `/data/adb/hideallroot/config.conf`，由 `action.sh` / WebUI 调整。

源码在仓库根 `jni/`，由顶层 `build.sh` 编译后放入本目录 `zygisk/<ABI>.so`。

> 注意：本模块刻意未使用 `setOption(DLCLOSE_MODULE_LIBRARY)`，避免 PLT Hook 悬空指针导致目标进程崩溃。
