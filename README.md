# HideAllRoot · Zygisk 一体化 Root 痕迹隐藏模块（v2.0）

> 基于 **Zygisk** 的 Magisk / KernelSU / APatch 通用 Root 痕迹隐藏模块，
> 采用 **VFS 级卸载 + PLT Hook 双引擎**，针对 **Momo / Ruru / 春秋 (SpringRoot) /
> RootBeer / Play Integrity** 做全维度对抗，内置 **WebUI 配置面板** 与
> **终端菜单**，可迭代、可编译、合规开源。
>
> **开发者：RootModLab** · 当前版本 **v2.0** (versionCode 10)

---

## 一、架构分析

| 维度 | 作用目标 | 实现位置 | 兼容框架 |
|------|---------|---------|---------|
| 静态痕迹 | 危险属性重置、日志屏蔽 | `post-fs-data.sh` / `service.sh` | Magisk ? KSU ? APatch ? |
| VFS 卸载 | Magisk tmpfs / overlay 挂载 | `zygisk/libzygisk.so`（应用私有命名空间 `umount2(MNT_DETACH)`） | Magisk ?（原生 Zygisk）<br>KSU/APatch ?? 需 **ZygiskNext** |
| 原生 Hook | open/openat/openat2/access/stat/readlink/syscall… | `zygisk/libzygisk.so`（C++） | 同上 |
| 进程/包名 | magiskd、zygiskd、lspd 枚举隐藏 | `zygisk/libzygisk.so` | 同上 |
| 配置 UI | 开关 / 目标 / 包名 | `webui/`（构建时兼容生成 `webroot/`）+ `action.sh` | KSU/APatch 原生 WebUI ?<br>Magisk 需 WebUI 扩展 |

> ?? **框架差异说明**：Magisk 原生支持 Zygisk；KernelSU / APatch 本身**不带** Zygisk，
> 必须先安装社区模块 **ZygiskNext** 后，本模块的 `zygisk/` 原生库才会加载。
> 静态隐藏（`post-fs-data.sh` + `sepolicy.rule`）在三框架下均生效，即“Magisk 支持的模块
> KSU 可能不支持”的本质——原生 Hook 部分需要 ZygiskNext 兜底。

### 模块文件树

```
HideAllRoot/
├── module.prop            # 模块元数据（zygisk=yes，author=RootModLab，v2.0）
├── customize.sh           # 安装预处理：环境识别 + DenyList 兜底
├── post-fs-data.sh        # 开机早期：属性重置 / 日志屏蔽 / 防砖
├── service.sh             # 开机晚期：二次校正属性
├── action.sh              # 终端配置菜单（无图形环境 UI）
├── sepolicy.rule          # SELinux 放行规则（tmpfs/overlay unmount）
├── config/
│   └── default.conf       # 默认配置（安装时写入 /data/adb/hideallroot/）
├── webui/                 # WebUI 源（仪表盘/配置/包名/日志/关于 五页）
│   ├── index.html
│   └── main.js
├── zygisk/                # 编译产物（四架构）
│   ├── arm64/libzygisk.so
│   ├── arm/libzygisk.so
│   ├── x86/libzygisk.so
│   └── x64/libzygisk.so
├── jni/                   # 源码（不参与打包）
│   ├── Android.mk
│   ├── Application.mk
│   ├── include/zygisk.hpp # 公开 API 头（已按 Magisk ABI 还原）
│   └── main.cpp           # Zygisk 原生模块（v2.0 双引擎）
├── build.sh               # 一键编译 + 打包（含 webroot 兼容副本）
└── README.md
```

---

## 二、检测维度覆盖（Momo / Ruru / 春秋 / Play Integrity）

| 检测维度 | 对抗手段 | 实现 |
|---------|---------|------|
| 文件层 `su`/`magisk`/`ksu`/`apatch`/`zygisk`/`lspd` | PLT Hook + 直接 `syscall()` 拦截 `open/openat/openat2/access/faccessat/faccessat2`，**精确前缀 + 词边界**匹配（修复 v1.x `strstr` 误杀），命中返回 `ENOENT` | `main.cpp` |
| 元数据 `stat/lstat/fstatat/statx/__xstat/__lxstat/__fxstatat` + `readlink/readlinkat` | 同上路径匹配；覆盖 `openat2`/`statx`/`faccessat2` 等新版接口 | `main.cpp` |
| **VFS 级卸载** | `preAppSpecialize` 解析 `/proc/self/mountinfo`，在应用私有命名空间 `umount2(MNT_DETACH)` Magisk tmpfs / overlay 挂载（真卸载，非仅 ENOENT） | `main.cpp` |
| 系统属性 `ro.magisk*` / `ro.ksu*` / `ro.apatch*` / `ro.debuggable` / `ro.build.tags` | Hook `__system_property_get` 返回出厂值；Hook `__system_property_find` 对隐藏属性返回 `nullptr` | `main.cpp` |
| 进程枚举 `magiskd`/`zygiskd`/`ksud`/`apd` | `readdir/readdir64` 过滤 + `connect()` UNIX socket 拦截 + `kill()` 拦截 + PID→comm 缓存(TTL) | `main.cpp` |
| Native 层 `libzygisk.so` / `frida` / `gum` / `xhook` / `memfd:` | 过滤 `/proc/self/maps`、`/proc/<pid>/maps` 特征行 + `prctl(PR_SET_VMA_ANON_NAME)` 匿名映射重命名防御 | `main.cpp` |
| 应用列表（春秋重点） | 过滤 `/data/system/packages.xml`、`/data/system/packages.list` 中 root 管理器包名 | `main.cpp` |
| 反调试（Ruru 自附加） | Hook `ptrace` 阻断 `PTRACE_ATTACH/SEIZE` 到自身；过滤 `/proc/self/status` 将 `TracerPid` 强制归零 | `main.cpp` |
| 环境变量 / PATH | `preAppSpecialize` 清洗 `ZYGISK_NATIVE`/`MAGISK`/`KSU`/`APATCH` 等变量并过滤 PATH | `main.cpp` |
| SELinux 上下文泄露 | 过滤 `/proc/self/attr/current` 与 `/proc/<pid>/attr/current`，将含 `magisk`/`zygisk`/`su:`/`ksu` 的上下文伪装为 `u:r:untrusted_app:s0` | `main.cpp` |
| 挂载点异常（Momo 重点） | 过滤 `/proc/mounts`、`/proc/self/mountinfo` 中 magisk/ksu/apatch/zygisk 挂载行 | `main.cpp` |
| 守护进程 socket | 过滤 `/proc/net/unix` 中 `magiskd`/`zygiskd`/`ksud`/`apd` 等 socket | `main.cpp` |
| 注入库路径（`dladdr`） | Hook `dladdr` 命中注入库时返回 0（伪装“无法解析”，而非返回空文件名暴露 hook） | `main.cpp` |
| 内核模块列表 | 过滤 `/proc/modules` 中 `magisk`/`zygisk`/`ksu`/`apatch`/`kernelsu` 等行 | `main.cpp` |
| 配置驱动 | 全部行为由 `/data/adb/hideallroot/config.conf` 决定，WebUI / 终端菜单即时调整，无需重编译 | 全部 |

---

## 三、配置键（v2.0）

配置文件位于 `/data/adb/hideallroot/config.conf`，所有开关 `1=开 0=关`：

| 键 | 含义 |
|----|------|
| `ENABLE` | 总开关，关闭后一切隐藏停止 |
| `ENABLE_FILE_HIDE` | 文件层隐藏（open/openat/openat2/access/stat/readlink） |
| `ENABLE_PROP_HIDE` | 属性隐藏（`__system_property_get` / `__system_property_find`） |
| `ENABLE_PROC_HIDE` | 进程隐藏（readdir 过滤 + connect + kill + PID 缓存） |
| `ENABLE_MAPS_HIDE` | `/proc/<pid>/maps` 过滤 + 匿名映射重命名防御 |
| `ENABLE_MOUNT_HIDE` | `/proc/mounts` 与 `/proc/self/mountinfo` 过滤 |
| `ENABLE_SOCKET_HIDE` | `/proc/net/unix` 守护进程 socket 过滤 |
| `ENABLE_DEBUG_HIDE` | `/proc/self/status` TracerPid 清零 + 自 ptrace 拦截 |
| `ENABLE_UNMOUNT` | VFS 级卸载 Magisk tmpfs / overlay |
| `ENABLE_ENV_CLEAN` | 环境变量与 PATH 清洗 |
| `ENABLE_ZYGISK_CLEAN` | 激进清理 zygisk/frida/gum/xhook 的 maps 痕迹 |
| `TARGET_MODE` | `0`=全部应用 `1`=仅检测工具 `2`=仅自定义包名 |
| `TARGET_PKGS` | 检测工具包名（TARGET_MODE=1，逗号分隔） |
| `CUSTOM_PKGS` | 自定义包名（TARGET_MODE=2，逗号分隔） |

---

## 四、编译与发布

```bash
# 本地编译四架构并打包 HideAllRoot.zip
export ANDROID_NDK_HOME=/opt/android-ndk   # 或把 NDK 放到 /opt/android-ndk
bash build.sh
```

CI（`.github/workflows/build.yml`）使用 `nttld/setup-ndk@v1`（r26d）自动编译；
推送形如 `v*` 的 tag 会自动创建 GitHub Release 并附上 `HideAllRoot.zip`。

> 注意：本模块刻意**未**使用 `setOption(DLCLOSE_MODULE_LIBRARY)`——PLT Hook 与
> 卸载模块库会留下悬空函数指针导致目标进程崩溃；`.so` 通过 `/proc/self/maps`
> 行过滤隐藏，功能等价且更安全。

---

## 五、合规与免责

本项目为开源安全研究工具，遵循 Magisk 通用模块规范。请仅在你拥有或获授权的设备上使用，
遵守所在地区法律法规。模块不修改系统分区、不植入后门，深度隐藏均在应用进程命名空间内完成。
