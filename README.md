# HideAllRoot · 一键全隐藏 Root（Zygisk 一体化隐藏模块）

> 基于 **Zygisk** 的 Magisk / KernelSU / APatch 通用 Root 痕迹隐藏模块，
> 针对 **Momo / Ruru / 春秋 (SpringRoot) / RootBeer** 等检测工具做全维度对抗，
> 内置 **WebUI 配置面板** 与 **终端菜单**，可迭代、可编译、合规开源。
>
> **开发者：MJH** · 当前版本 **v1.4**

---

## 一、架构分析

| 维度 | 作用目标 | 实现位置 | 兼容框架 |
|------|---------|---------|---------|
| 静态痕迹 | 危险属性重置、日志屏蔽 | `post-fs-data.sh` / `service.sh` | Magisk ✅ KSU ✅ APatch ✅ |
| 原生 Hook | open/stat/getprop/popen/ptrace… | `zygisk/libzygisk.so`（C++） | Magisk ✅（原生 Zygisk）<br>KSU/APatch ⚠️ 需 **ZygiskNext** |
| 进程/包名 | magiskd、zygiskd、lspd 枚举隐藏 | `zygisk/libzygisk.so` | 同上 |
| 配置 UI | 开关 / 目标 / 包名 | `webroot/` + `action.sh` | KSU/APatch 原生 WebUI ✅<br>Magisk 需 WebUI 扩展 |

> ⚠️ **框架差异说明**：Magisk 原生支持 Zygisk；KernelSU / APatch 本身**不带** Zygisk，
> 必须先安装社区模块 **ZygiskNext** 后，本模块的 `zygisk/` 原生库才会加载。
> 静态隐藏（`post-fs-data.sh` + `sepolicy.rule`）在三框架下均生效，这就是
> “Magisk 支持的模块 KSU 可能不支持” 的本质——原生 Hook 部分需要 ZygiskNext 兜底。

### 模块文件树

```
HideAllRoot/
├── module.prop            # 模块元数据（zygisk=yes）
├── customize.sh           # 安装预处理：环境识别 + DenyList 兜底
├── post-fs-data.sh        # 开机早期：属性重置 / 日志屏蔽 / 防砖
├── service.sh             # 开机晚期：二次校正属性
├── action.sh              # 终端配置菜单（无图形环境 UI）
├── sepolicy.rule          # SELinux 放行规则
├── config/
│   └── default.conf       # 默认配置（安装时写入 /data/adb/hideallroot/）
├── webroot/               # WebUI（液态玻璃 + 霓虹）
│   ├── index.html
│   ├── style.css
│   └── main.js
├── zygisk/
│   ├── arm64/libzygisk.so # 编译产物（64 位）
│   └── arm/libzygisk.so   # 编译产物（32 位）
├── jni/                   # 源码（不参与打包）
│   ├── Android.mk
│   ├── Application.mk
│   ├── include/zygisk.hpp # 公开 API 头（已按 Magisk ABI 还原）
│   └── main.cpp           # Zygisk 原生模块
├── build.sh               # 一键编译 + 打包
└── README.md
```

---

## 二、检测维度覆盖（Momo / Ruru / 春秋）

| 检测维度 | 对抗手段 | 实现 |
|---------|---------|------|
| 文件层 `su`/`magisk`/`lspd` 路径 | Hook `open/openat/access/fstat/fopen/opendir/readlink/realpath` 返回 `ENOENT` | `main.cpp` |
| 系统属性 `ro.magisk*` / `ro.debuggable` / `ro.build.tags` | Hook `__system_property_get` 返回出厂值 | `main.cpp` |
| 进程枚举 `magiskd`/`zygiskd`/`lsposed` | 拦截 `/proc/<pid>/{cmdline,comm,status,stat,wchan,exe}` 与 `/proc/<pid>` 目录返回 `ENOENT` | `main.cpp` |
| 命令执行 `su`/`magisk` | Hook `popen/system/execve` 拦截 | `main.cpp` |
| Native 层 `libzygisk.so` 映射 | 拦截 `/proc/self/maps`、`/proc/<pid>/maps` 读取并抹除特征行 | `main.cpp` |
| 应用列表（春秋重点） | 过滤 `/data/system/packages.xml`、`/data/system/packages.list` 中 Magisk/LSPosed 包名 | `main.cpp` |
| 反调试（Ruru 自附加） | Hook `ptrace` 阻断 `PTRACE_ATTACH/SEIZE` 到自身 | `main.cpp` |
| 解锁 Bootloader 属性 | Hook `__system_property_get` 将 `ro.boot.verifiedbootstate`→`green`、`ro.boot.flash.locked`→`1`、`ro.oem.lockstate`→`locked` 等 | `main.cpp` |
| 调试器 `TracerPid` | 过滤 `/proc/self/status` 将 `TracerPid` 强制归零 | `main.cpp` |
| 挂载点异常（Momo 重点） | 过滤 `/proc/mounts`、`/proc/self/mountinfo` 中 magisk/ksu/apatch/zygisk 挂载行 | `main.cpp` |
| 守护进程 socket | 过滤 `/proc/net/unix` 中 `magiskd`/`zygiskd`/`ksud`/`apd` 等 socket | `main.cpp` |
| 注入框架内存特征 | 过滤 `/proc/self/maps` 中 `frida`/`xhook`/`memfd:`/`zygisk_module_entry` 等行（含 Ruru 的 /memfd:jit-cache 扫描） | `main.cpp` |
| 注入库路径（`dladdr`） | Hook `dladdr` 命中注入库时返回 0（伪装“无法解析”，而非返回空文件名暴露 hook） | `main.cpp` |
| fd 符号链接 | 隐藏 `/proc/self/fd` 中指向 magisk/zygisk 的链接（伪装为失效） | `main.cpp` |
| 内核模块列表 | 过滤 `/proc/modules` 中 `magisk`/`zygisk`/`ksu`/`apatch`/`kernelsu` 等行 | `main.cpp` |
| SELinux 上下文泄露 | 过滤 `/proc/<pid>/attr/current`，将含 `magisk`/`zygisk`/`su:`/`ksu` 的上下文伪装为 `u:r:untrusted_app:s0` | `main.cpp` |
| 新版文件/状态接口 | Hook `openat2` / `statx`，阻断对隐藏路径的打开与 stat | `main.cpp` |
| 目录枚举 | Hook `readdir`/`readdir64`，跳过 `magisk`/`zygisk`/`lspd`/模块目录等条目 | `main.cpp` |
| 文件游标同步 | Hook `lseek`/`lseek64` 同步缓冲读游标，避免 `read()`+`lseek`+`read()` 内容错位 | `main.cpp` |
| build.prop 直读 | 过滤 `/system/build.prop` 等中 `test-keys`/`userdebug`/`orange` 行（与属性 Hook 互补） | `main.cpp` |
| 扩充的 Root 框架 / 应用 | 隐藏包名与路径覆盖 Magisk 全分支（Kitsune）、KernelSU、APatch、LSPosed、Riru、TaiChi、EdXposed、SuperSU、Shamiko、Hide-My-Applist、BusyBox 等 | `main.cpp` |
| DenyList 兜底 | 安装时把检测工具加入 Magisk DenyList（不强制，由模块接管） | `customize.sh` |

---

## 三、原生模块设计要点（`jni/main.cpp`）

1. **配置驱动**：每次应用 `preAppSpecialize` 读取 `/data/adb/hideallroot/config.conf`，
   所有开关、目标模式、包名列表均可经 WebUI 热更新（对新启动的应用立即生效）。
2. **按进程靶向**：`TARGET_MODE=0` 隐藏全部应用；`=1` 仅检测工具；`=2` 仅自定义包名。
   非目标进程完全不挂钩，零性能损耗、零副作用。
3. **PLT 批量挂钩**：通过 `api->pltHookRegister(".*", sym, ...)` 对所有已加载库做 GOT 挂钩，
   覆盖应用及其依赖库对 libc 的全部调用。
4. **maps / 包列表缓冲过滤**：对 `/proc/*/maps` 与 `packages.xml` 做整文件读取→按特征行过滤→
   经 `read`/`pread64` 喂回，做到“内容级”抹除而非简单拒绝。
5. **防递归**：Hook 内部一律通过捕获的 `orig_*` 原版函数访问文件/属性，日志仅用 `logd`，
   绝不在 Hook 路径内调用被 Hook 的函数。
6. **防砖**：`post-fs-data.sh` 检测 `/data/local/tmp/disable_hideallroot` 即自动 `touch disable`。

> ABI 说明：`jni/include/zygisk.hpp` 已按 Magisk 内部 `api_abi_v2` 内存布局精确还原，
> `Api` 类严格对齐 `impl → registerModule → 8 个回调` 的偏移，编译即可正确链接加载器。

---

## 四、构建与打包

### 要求
- Android NDK **r25+**（`ANDROID_NDK_HOME` 指向 NDK，或置于 `/opt/android-ndk`）
- 已安装 `zip`

### 一键构建
```bash
cd HideAllRoot
bash build.sh
# 产物: HideAllRoot.zip（可直接刷入）
# 同时生成 zygisk/arm64/libzygisk.so 与 zygisk/arm/libzygisk.so
```
`build.sh` 流程：① `ndk-build` 编译 `arm64-v8a` + `armeabi-v7a` →
② 拷贝 `.so` 到 `zygisk/<abi>/` → ③ 排除 `jni/`、`out/` 等源码与中间产物打包为 zip。

---

## 五、刷入与测试

1. **刷入**：Magisk / KSU / APatch 管理器 → 模块 → 从本地安装 `HideAllRoot.zip` → 重启。
   - KSU / APatch 用户：**先安装 ZygiskNext**，否则原生 Hook 不生效。
2. **配置**：管理器内打开本模块 → WebUI 面板（或终端 `action.sh` 菜单）。
3. **测试**（纯净环境，勿叠加其它优化/隐藏模块以免留痕）：
   - 打开 **Momo**：环境分区无异常、无 Magisk/Su 痕迹。
   - 打开 **Ruru**：全部检测项 Pass，且 `/proc/self/maps` 中无 `libzygisk` 字样。
   - 打开 **春秋 (SpringRoot)**：无 Root、无 Magisk/LSPosed 包名。
4. **自检**：WebUI「运行自检」直接回显 `ro.debuggable`、`ro.build.tags`、
   `su` 路径、`ro.magisk.version` 等关键项。

---

## 六、专家建议 / 排错

- **SELinux**：若某 ROM 报 `avc: denied` 导致注入失败，`dmesg | grep 'avc: denied'`
  定位后把对应 `allow` 规则追加到 `sepolicy.rule` 重启即可。
- **Android 14+ 严格机型**：部分 OEM TEE / SELinux 强校验仍可能拦截，属硬件/固件层限制，
  非模块可完全绕过——属预期（检测工具持续迭代，不存在永久 100% 方案）。
- **调试日志**：原生层日志 tag 为 `HideAllRoot`，`logcat -s HideAllRoot` 观察挂钩是否生效。
- **回退**：创建 `/data/local/tmp/disable_hideallroot` 后重启即自动停用模块；
  或管理器中直接禁用本模块。
- **最小化痕迹**：测试时只保留本模块，避免与 Shamiko / Hide My App List 等叠加产生冲突特征。

---

## 七、合规与许可

本模块仅用于**设备所有者对自身设备的隐私与可控性管理**，所有代码开源、可在本地审查编译。
请勿用于规避付费内容、金融风控作弊等违反服务条款的场景。

---

# HideAllRoot (English)

> A **Zygisk**-based, all-in-one root-trace hiding module for **Magisk / KernelSU / APatch**,
> built to defeat the **Momo / Ruru / SpringRoot (春秋) / RootBeer** detection tools across every dimension.
> Ships with a **WebUI config panel** and a **terminal menu**. Iterative, compilable, and open-source.
>
> **Developer: MJH** · **v1.4**

## Architecture

| Layer | Target | Location | Frameworks |
|-------|--------|----------|------------|
| Static traces | reset dangerous props, hide logs | `post-fs-data.sh` / `service.sh` | Magisk ✅ KSU ✅ APatch ✅ |
| Native hooks | open/stat/getprop/popen/ptrace… | `zygisk/libzygisk.so` (C++) | Magisk ✅ (native Zygisk)<br>KSU/APatch ⚠️ needs **ZygiskNext** |
| Process/package | hide magiskd/zygiskd/lspd enumeration | `zygisk/libzygisk.so` | same as above |
| Config UI | toggles / targets / packages | `webroot/` + `action.sh` | KSU/APatch native WebUI ✅<br>Magisk needs a WebUI add-on |

> **Framework note:** Magisk supports Zygisk natively. KernelSU / APatch do **not** ship Zygisk —
> install the community module **ZygiskNext** first, otherwise the `zygisk/` native library will not load.
> The static hiding (`post-fs-data.sh` + `sepolicy.rule`) works on all three frameworks — that is exactly
> the meaning of "a Magisk-supported module may not be supported by KSU": the native-hook part needs ZygiskNext.

## Detection coverage (Momo / Ruru / SpringRoot)

| Dimension | Countermeasure | Implementation |
|-----------|----------------|----------------|
| File layer `su`/`magisk`/`lspd` paths | Hook open/openat/access/fstat/fopen/opendir/readlink/realpath → `ENOENT` | `main.cpp` |
| System props `ro.magisk*` / `ro.debuggable` / `ro.build.tags` | Hook `__system_property_get` → factory values | `main.cpp` |
| Process enum `magiskd`/`zygiskd`/`lsposed` | Block `/proc/<pid>/{cmdline,comm,status,stat,wchan,exe}` & `/proc/<pid>` dir → `ENOENT` | `main.cpp` |
| Command exec `su`/`magisk` | Hook popen/system/execve | `main.cpp` |
| Native `libzygisk.so` mapping | Filter `/proc/self/maps` & `/proc/<pid>/maps` line-by-line | `main.cpp` |
| App list (SpringRoot focus) | Filter `/data/system/packages.xml` / `packages.list` for Magisk/LSPosed/KSU/APatch packages | `main.cpp` |
| Anti-debug (Ruru self-attach) | Hook `ptrace` to block `PTRACE_ATTACH/SEIZE` on self | `main.cpp` |
| Bootloader-unlock props | Hook `__system_property_get`: `ro.boot.verifiedbootstate`→`green`, `ro.boot.flash.locked`→`1`, `ro.oem.lockstate`→`locked`, etc. | `main.cpp` |
| Debugger `TracerPid` | Filter `/proc/self/status`, force `TracerPid` to 0 | `main.cpp` |
| Mount anomalies (Momo focus) | Filter `magisk`/`ksu`/`apatch`/`zygisk` lines from `/proc/mounts` & `/proc/self/mountinfo` | `main.cpp` |
| Daemon sockets | Filter `magiskd`/`zygiskd`/`ksud`/`apd` from `/proc/net/unix` | `main.cpp` |
| Injection memory | Filter `frida`/`xhook`/`memfd:`/`zygisk_module_entry` lines from `/proc/self/maps` (incl. Ruru's /memfd:jit-cache scan) | `main.cpp` |
| Injection lib paths (`dladdr`) | Hook `dladdr` to strip `magisk`/`zygisk`/`frida`/`lsplant`/`xhook` library paths (Momo/Ruru probe via dladdr) | `main.cpp` |
| fd symlinks | Hide `/proc/self/fd` symlinks pointing at magisk/zygisk (pretend broken) | `main.cpp` |
| Kernel module list | Filter `magisk`/`zygisk`/`ksu`/`apatch`/`kernelsu` lines from `/proc/modules` | `main.cpp` |
| SELinux context leak | Filter `/proc/<pid>/attr/current`, rewrite contexts containing `magisk`/`zygisk`/`su:`/`ksu` to `u:r:untrusted_app:s0` | `main.cpp` |
| New file/stat APIs | Hook `openat2` / `statx` to block opening/stat'ing hidden paths | `main.cpp` |
| Directory enumeration | Hook `readdir`/`readdir64` to skip `magisk`/`zygisk`/`lspd`/module-dir entries | `main.cpp` |
| File cursor sync | Hook `lseek`/`lseek64` to keep the buffered read cursor in sync (no desync on read()+lseek+read()) | `main.cpp` |
| build.prop direct read | Filter `test-keys`/`userdebug`/`orange` lines from `/system/build.prop` etc. (complements property hook) | `main.cpp` |
| Expanded frameworks/apps | Hide packages & paths for Magisk (all forks), KernelSU, APatch, LSPosed, Riru, TaiChi, EdXposed, SuperSU, Shamiko, Hide-My-Applist, BusyBox… | `main.cpp` |
| DenyList fallback | Add detectors to Magisk DenyList at install (optional, module takes over) | `customize.sh` |

## Build & Package

Requirements: Android NDK **r25+** (`ANDROID_NDK_HOME`, or `/opt/android-ndk`), and `zip`.

```bash
cd HideAllRoot
bash build.sh
# output: HideAllRoot.zip (flashable)
# also produces zygisk/arm64/libzygisk.so and zygisk/arm/libzygisk.so
```

`build.sh`: ① `ndk-build` for `arm64-v8a` + `armeabi-v7a` →
② copy `.so` into `zygisk/<abi>/` → ③ package into zip excluding `jni/`, `out/`, etc.

> **CI:** Pushing to `main` builds the zip as a downloadable **artifact**; pushing a `v*` tag
> creates a GitHub **Release** automatically (see `.github/workflows/build.yml`).

## Flash & Test

1. Flash `HideAllRoot.zip` via Magisk / KSU / APatch manager → reboot.
   KSU / APatch users: **install ZygiskNext first**, or native hooks will not load.
2. Configure via the manager's WebUI panel (or terminal `action.sh` menu).
3. Test in a clean environment (no other hiding modules):
   - **Momo**: no Magisk/Su traces in the environment section.
   - **Ruru**: all checks pass, and `/proc/self/maps` shows no `libzygisk`.
   - **SpringRoot (春秋)**: no Root, no Magisk/LSPosed packages.
4. Self-check: the WebUI "Run self-check" echoes `ro.debuggable`, `ro.build.tags`,
   the `su` path, and `ro.magisk.version`.

## Compliance & License

This module is intended only for **device owners managing the privacy and controllability of their own
devices**. All code is open-source and can be audited and compiled locally. Do not use it to bypass paid
content, financial-risk-control cheating, or other ToS-violating scenarios.
