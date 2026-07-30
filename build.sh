#!/usr/bin/env bash
#
# HideAllRoot v2.0 build script
# ------------------------------
# 1. 用 Android NDK 编译 libzygisk.so（arm64 / arm / x86 / x86_64）。
# 2. 拷贝到模块的 zygisk/<abi>/ 目录。
# 3. 将 webui/ 同步为 webroot/（标准管理器从 webroot/ 加载 WebUI）。
# 4. 打包成可刷入的 HideAllRoot.zip。
#
# 依赖：Android NDK（设置 ANDROID_NDK_HOME，或放在 /opt/android-ndk）。
#
set -euo pipefail

cd "$(dirname "$0")"                # 模块根目录
MODULE_DIR="$(pwd)"
OUT_DIR="$MODULE_DIR/out"
ZIP_NAME="HideAllRoot.zip"

NDK="${ANDROID_NDK_HOME:-/opt/android-ndk}"
if [ ! -x "$NDK/ndk-build" ]; then
    echo "ERROR: ndk-build 未找到，请设置 ANDROID_NDK_HOME 或安装 NDK 到 /opt/android-ndk" >&2
    exit 1
fi

echo "[*] NDK: $NDK"
echo "[*] 清理旧构建 ..."
rm -rf "$OUT_DIR" "$MODULE_DIR/libs" "$MODULE_DIR/obj"
mkdir -p "$OUT_DIR"

echo "[*] 编译 libzygisk.so (arm64-v8a, armeabi-v7a, x86, x86_64) ..."
"$NDK/ndk-build" NDK_PROJECT_PATH="$MODULE_DIR" \
    APP_BUILD_SCRIPT="$MODULE_DIR/jni/Android.mk" \
    NDK_APPLICATION_MK="$MODULE_DIR/jni/Application.mk" \
    NDK_LIBS_OUT="$OUT_DIR/libs" \
    NDK_OUT="$OUT_DIR/obj"

echo "[*] 放置二进制（Magisk 官方规范：zygisk/<ABI>.so）..."
# 清理旧的非标准子目录布局（zygisk/arm64/libzygisk.so 等 Magisk 不加载）
rm -rf "$MODULE_DIR/zygisk/arm64" "$MODULE_DIR/zygisk/arm" \
       "$MODULE_DIR/zygisk/x86" "$MODULE_DIR/zygisk/x64" \
       "$MODULE_DIR/zygisk/x86_64"
mkdir -p "$MODULE_DIR/zygisk"
for abi in arm64-v8a armeabi-v7a x86 x86_64; do
    src="$OUT_DIR/libs/$abi/libzygisk.so"
    if [ -f "$src" ]; then
        cp -f "$src" "$MODULE_DIR/zygisk/${abi}.so"
        echo "    ✓ zygisk/${abi}.so"
    else
        echo "    ✗ $abi (missing)"
    fi
done

# 标准管理器（Magisk / KSU / APatch）从 webroot/ 加载 WebUI；
# v2.0 源码位于 webui/，此处复制一份到 OUT_DIR/webroot 并加入压缩包，
# 既满足 spec 的 webui/ 目录，又保证标准管理器可加载。
echo "[*] 生成 webroot/ 兼容副本 ..."
rm -rf "$OUT_DIR/webroot"
mkdir -p "$OUT_DIR/webroot"
cp -rf "$MODULE_DIR/webui/." "$OUT_DIR/webroot/"

echo "[*] 打包 $ZIP_NAME ..."
rm -f "$MODULE_DIR/$ZIP_NAME"
( cd "$MODULE_DIR" && zip -r -q "$MODULE_DIR/$ZIP_NAME" . \
    -x 'jni/*' -x 'out/*' -x 'libs/*' -x 'obj/*' -x '.git/*' -x '*.zip' \
       -x 'build.sh' -x 'README.md' -x '.clang-format' -x '.github/*' -x 'webroot/*' )
# 追加 webroot 副本（来自 OUT_DIR，避免污染仓库）
( cd "$OUT_DIR" && zip -r -q "$MODULE_DIR/$ZIP_NAME" webroot )

echo "[*] Done -> $MODULE_DIR/$ZIP_NAME"
ls -lh "$MODULE_DIR/$ZIP_NAME"
