# HideAllRoot（双模块）

基于 **Zygisk** 的 Magisk / KernelSU / APatch 通用 Root 痕迹隐藏方案，**双模块架构**：

- **仓库根是容器**，不是 Magisk 模块。两个子目录各自独立可刷入。
- [`HideAllRoot-Runtime`](HideAllRoot-Runtime)：Zygisk 运行时引擎（PLT hook + seccomp 稳妥 PoC）。
- [`HideAllRoot-System`](HideAllRoot-System)：系统级加固（属性伪装 / SELinux / 挂载视图 / 痕迹清理）。

> 开发者：AceGuru-mjh · 当前版本 **v3.0** · 详细架构见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

---

## 安装顺序（必须）

```
1. Magisk / KernelSU / APatch（已安装）
       ↓
2. HideAllRoot-System.zip   ← 先装（准备系统环境）
       ↓
3. HideAllRoot-Runtime.zip  ← 后装（依赖 System 配置，缺失则安装中止）
       ↓
4. 重启
```

> KernelSU / APatch 本身不带 Zygisk，需额外安装 **ZygiskNext** 后 Runtime 才会生效。

## 卸载顺序（反向）

```
1. 卸载 Runtime → 2. 卸载 System → 3. 重启
```

---

## 模块文件树

```
RootModLab/                         ← 仓库根（容器）
├── build.sh                        ← 顶层构建脚本（打包两个模块 zip）
├── jni/                            ← 共享原生源码（编译产物不进 zip）
├── docs/                           ← 共享文档（架构/覆盖表/编译）
├── HideAllRoot-Runtime/            ← 模块 1：Zygisk 运行时
│   ├── module.prop  customize.sh  uninstall.sh  sepolicy.rule
│   ├── config/default.conf
│   ├── zygisk/<ABI>.so
│   ├── webui/  action.sh
└── HideAllRoot-System/             ← 模块 2：系统级
    ├── module.prop  customize.sh  uninstall.sh
    ├── post-fs-data.sh  service.sh  action 相关脚本
    ├── sepolicy.rule  config/default.conf
```

## 编译

```bash
export ANDROID_NDK_HOME=/opt/android-ndk
bash build.sh
# 产出 release/HideAllRoot-Runtime.zip 与 release/HideAllRoot-System.zip
```

详见 [docs/BUILD_GUIDE.md](docs/BUILD_GUIDE.md) 与 [docs/DETECTION_COVERAGE.md](docs/DETECTION_COVERAGE.md)。

## 合规与免责

开源安全研究工具，仅可在你拥有或获授权的设备上使用，遵守所在地法律法规。模块不修改系统分区、不植入后门，深度隐藏均在应用进程命名空间内完成。
