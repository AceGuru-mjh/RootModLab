# 双模块协同架构 (Option B)

仓库根是**容器**，不再是 Magisk 模块。两个独立模块各自可单独刷入：

| 模块 | id | 职责 | 时机 |
|------|----|------|------|
| `HideAllRoot-System` | `hideallroot_system` | boot 早期 VFS/属性伪装/resetprop、SELinux 注入、挂载命名空间准备、痕迹清理 | `post-fs-data.sh` / `service.sh` |
| `HideAllRoot-Runtime` | `hideallroot_runtime` | Zygisk `.so` 注入：PLT hook 引擎 + seccomp-bpf 稳妥 PoC（默认关） | Zygote fork 应用进程时 |

## 依赖关系

```
Magisk / KernelSU / APatch
        │
        ├─ 1. HideAllRoot-System.zip   ← 先装（准备系统环境）
        │
        ├─ 2. HideAllRoot-Runtime.zip  ← 后装（依赖 System 配置）
        │        └─ customize.sh 检测 /data/adb/modules/hideallroot_system 是否存在，缺失则 abort
        │
        └─ 3. 重启
```

卸载顺序相反：先 Runtime，后 System。

## 共享状态

两个模块通过 `/data/adb/hideallroot/` 共享配置与状态：

- `config.conf`：Runtime 的 hook 开关（由 Runtime `customize.sh` 首次安装时从 `config/default.conf` 写入；`action.sh` / WebUI 编辑此文件）。
- `system_status`：System 模块写入的阶段完成标记。

## 源码布局

- `jni/`：共享原生源码（`main.cpp` + `seccomp_poc.cpp` + `Android.mk`），编译产物为 `libzygisk.so`，由顶层 `build.sh` 放入 `HideAllRoot-Runtime/zygisk/<ABI>.so`。
- `HideAllRoot-Runtime/` 下的 `webui/`、`zygisk/`、`config/`、`action.sh`、`customize.sh`、`sepolicy.rule`、`uninstall.sh` 属于 Runtime。
- `HideAllRoot-System/` 下的 shell 脚本与 `sepolicy.rule`、`config/` 属于 System。

## 安装顺序为什么重要

Runtime 的 Zygisk 库在应用进程内做深度隐藏（open/openat 拦截、getdents64 过滤、`/proc/self/environ` 清洗、seccomp PoC 等）。这些隐藏依赖 System 模块在 boot 早期准备好的干净挂载视图与属性伪装——若先装 Runtime 后装 System，开机早期视图未就绪，部分检测项会在 System 生效前被读取。
