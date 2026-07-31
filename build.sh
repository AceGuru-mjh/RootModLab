#!/usr/bin/env bash
#
# HideAllRoot 双模块顶层构建脚本 (Option B: 仓库根 = 容器)
# ----------------------------------------------------------
# 1. 用 Android NDK 编译共享 jni/ 源码 -> libzygisk.so (四架构)
# 2. 拷贝到 HideAllRoot-Runtime/zygisk/<ABI>.so (Magisk 官方命名)
# 3. 生成 Runtime 的 webroot/ 兼容副本 (标准管理器从 webroot/ 加载 WebUI)
# 4. 分别打包 HideAllRoot-Runtime.zip 与 HideAllRoot-System.zip
#
# 依赖: Android NDK (设置 ANDROID_NDK_HOME, 或放到 /opt/android-ndk)
#
set -euo pipefail

cd "$(dirname "$0")"            # 仓库根目录
ROOT_DIR="$(pwd)"
OUT_DIR="$ROOT_DIR/out"
RELEASE_DIR="$ROOT_DIR/release"
RUNTIME_DIR="$ROOT_DIR/HideAllRoot-Runtime"
SYSTEM_DIR="$ROOT_DIR/HideAllRoot-System"

NDK="${ANDROID_NDK_HOME:-/opt/android-ndk}"
if [ ! -x "$NDK/ndk-build" ]; then
    echo "ERROR: ndk-build 未找到，请设置 ANDROID_NDK_HOME 或安装 NDK 到 /opt/android-ndk" >&2
    exit 1
fi

echo "[*] NDK: $NDK"
echo "[*] 清理旧构建 ..."
rm -rf "$OUT_DIR" "$RELEASE_DIR" "$RUNTIME_DIR/libs" "$RUNTIME_DIR/obj"
mkdir -p "$OUT_DIR" "$RELEASE_DIR"

echo "[*] 编译共享 jni/ 源码 (arm64-v8a, armeabi-v7a, x86, x86_64) ..."
"$NDK/ndk-build" NDK_PROJECT_PATH="$ROOT_DIR" \
    APP_BUILD_SCRIPT="$ROOT_DIR/jni/Android.mk" \
    NDK_APPLICATION_MK="$ROOT_DIR/jni/Application.mk" \
    NDK_LIBS_OUT="$OUT_DIR/libs" \
    NDK_OUT="$OUT_DIR/obj"

echo "[*] 放置 Zygisk 原生库 (Magisk 官方规范: zygisk/<ABI>.so) ..."
# 清理旧的非标准子目录布局 (zygisk/arm64/libzygisk.so 等 Magisk 不加载)
rm -rf "$RUNTIME_DIR/zygisk/arm64" "$RUNTIME_DIR/zygisk/arm" \
       "$RUNTIME_DIR/zygisk/x86" "$RUNTIME_DIR/zygisk/x64" "$RUNTIME_DIR/zygisk/x86_64"
mkdir -p "$RUNTIME_DIR/zygisk"
for abi in arm64-v8a armeabi-v7a x86 x86_64; do
    src="$OUT_DIR/libs/$abi/libzygisk.so"
    if [ -f "$src" ]; then
        cp -f "$src" "$RUNTIME_DIR/zygisk/${abi}.so"
        echo "    ✓ zygisk/${abi}.so"
    else
        echo "    ✗ $abi (missing)"
    fi
done

echo "[*] 生成 Runtime webroot/ 兼容副本 ..."
rm -rf "$OUT_DIR/webroot"
mkdir -p "$OUT_DIR/webroot"
cp -rf "$RUNTIME_DIR/webui/." "$OUT_DIR/webroot/"

zip_runtime() {
    local zip="$RELEASE_DIR/HideAllRoot-Runtime.zip"
    rm -f "$zip"
    ( cd "$RUNTIME_DIR" && zip -r -q "$zip" . \
        -x 'jni/*' -x 'src/*' -x 'out/*' -x 'libs/*' -x 'obj/*' \
           -x '.git/*' -x '*.zip' -x 'build.sh' -x 'README.md' \
           -x '.clang-format' -x '.github/*' -x 'webroot/*' )
    ( cd "$OUT_DIR" && zip -r -q "$zip" webroot )
    echo "    ✓ $zip"
}

zip_system() {
    local zip="$RELEASE_DIR/HideAllRoot-System.zip"
    rm -f "$zip"
    ( cd "$SYSTEM_DIR" && zip -r -q "$zip" . \
        -x 'jni/*' -x 'src/*' -x 'out/*' -x 'libs/*' -x 'obj/*' \
           -x '.git/*' -x '*.zip' -x 'README.md' -x '.github/*' )
    echo "    ✓ $zip"
}

echo "[*] 打包 HideAllRoot-Runtime.zip ..."
zip_runtime
echo "[*] 打包 HideAllRoot-System.zip ..."
zip_system

echo "[*] Done -> $RELEASE_DIR/"
ls -lh "$RELEASE_DIR/"
