# 检测维度覆盖（Momo / Ruru / 春秋 / Play Integrity）

> 下表汇总当前 Runtime（Zygisk PLT hook 引擎）+ System（boot 加固）已覆盖的对抗项。
> seccomp-bpf 项为稳妥 PoC，默认关闭（`ENABLE_SECCOMP_POC=0`）。

| 检测维度 | 对抗手段 | 实现位置 |
|---------|---------|---------|
| 文件层 `su`/`magisk`/`ksu`/`apatch`/`zygisk`/`lspd` | PLT Hook + 直接 `syscall()` 拦截 `open/openat/openat2/access/faccessat*`，精确前缀 + 词边界匹配，命中返回 `ENOENT` | Runtime `main.cpp` |
| 元数据 `stat/lstat/fstatat/statx/readlink/readlinkat` | 同上路径匹配 | Runtime `main.cpp` |
| 目录枚举 `getdents64` | 过滤 `/proc` 下 root 相关条目 | Runtime `main.cpp` |
| 环境变量泄露 | `preAppSpecialize` 清洗 `ZYGISK_NATIVE`/`MAGISK`/`KSU`/`APATCH` 等，过滤 `/proc/self/environ` | Runtime `main.cpp` |
| 系统属性 `ro.magisk*` / `ro.debuggable` / `ro.build.tags` | `__system_property_get`/`find` Hook 返回出厂值；System 侧 `resetprop` 伪装 | Runtime + System |
| 进程枚举 `magiskd`/`zygiskd`/`ksud` | `readdir` 过滤 + `connect()` UNIX socket 拦截 + `kill()` 拦截 | Runtime `main.cpp` |
| Native 层 `libzygisk.so`/`frida`/`gum` | 过滤 `/proc/self/maps` 特征行 | Runtime `main.cpp` |
| 应用列表（春秋重点） | 过滤 `packages.xml`/`packages.list` 中 root 管理器包名 | Runtime `main.cpp` |
| 反调试（Ruru 自附加） | Hook `ptrace` 阻断自附加；`/proc/self/status` TracerPid 清零 | Runtime `main.cpp` |
| 挂载点异常 | 过滤 `/proc/mounts`、`/proc/self/mountinfo`；VFS 级 `umount2(MNT_DETACH)` | Runtime + System |
| SELinux 上下文泄露 | 过滤 `/proc/self/attr/current` 伪装为 `u:r:untrusted_app:s0` | Runtime `main.cpp` |
| 守护进程 socket | 过滤 `/proc/net/unix` | Runtime `main.cpp` |
| `dladdr` 注入库路径 | 命中注入库时返回 0 | Runtime `main.cpp` |
| 内核模块列表 | 过滤 `/proc/modules` | Runtime `main.cpp` |
| 原始 `svc #0` syscall（seccomp PoC） | `SECCOMP_RET_TRAP` + SIGSYS 处理，仅拦截 libc 外的 `openat` | Runtime `seccomp_poc.cpp`（默认关） |

## 已知缺口（后续工作）

- `src/` 源码重构（按功能拆分 `seccomp_engine`/`linker_cleaner`/`path_filter`/`proc_hider`/`timing_guard`）尚未执行——当前仍是单文件 `jni/main.cpp` + `seccomp_poc.cpp`。
- seccomp 仅覆盖 `openat`，未覆盖 `open`/`read`/`close`（避免影响应用正常运行）。
- System 模块的 `system/` overlay 与 `bin/har_guard` 守护进程尚未实现。
