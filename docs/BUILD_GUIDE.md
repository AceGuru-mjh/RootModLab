# 编译指南

## 本地编译

需要 Android NDK（`ndk-build`）。

```bash
# 设置 NDK 路径
export ANDROID_NDK_HOME=/opt/android-ndk   # 或你的 NDK 路径

# 在仓库根目录执行顶层构建脚本
bash build.sh
```

脚本会：

1. `ndk-build` 编译共享 `jni/` 源码，产出四架构 `libzygisk.so`。
2. 拷贝到 `HideAllRoot-Runtime/zygisk/<ABI>.so`（Magisk 官方命名：`arm64-v8a.so` / `armeabi-v7a.so` / `x86.so` / `x86_64.so`）。
3. 生成 `HideAllRoot-Runtime/webroot/` 兼容副本（标准管理器从 `webroot/` 加载 WebUI）。
4. 在 `release/` 下产出 `HideAllRoot-Runtime.zip` 与 `HideAllRoot-System.zip`。

## 构建目标说明

| 目标 | 源码 | 产物 |
|------|------|------|
| Runtime | `jni/`（`main.cpp` + `seccomp_poc.cpp` + `Android.mk`/`Application.mk`） | `HideAllRoot-Runtime/zygisk/<ABI>.so` |
| System | 纯 shell，无需编译 | 直接打包 |

## CI

`.github/workflows/build.yml` 使用 `nttld/setup-ndk@v1`（r26d）自动编译；推送 `v*` tag 会创建 GitHub Release 并附上两个 zip。

## ABI / API 级别

- `APP_ABI := arm64-v8a armeabi-v7a x86 x86_64`
- `APP_PLATFORM := android-24`
- `APP_STL := c++_static`

见 `jni/Application.mk`。
