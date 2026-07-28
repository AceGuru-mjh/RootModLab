#!/usr/bin/env bash
#
# HideAllRoot build script
# -------------------------
# 1. Compiles libzygisk.so for arm64 + arm with the Android NDK.
# 2. Copies the binaries into the module's zygisk/<abi>/ folders.
# 3. Packages the whole module into HideAllRoot.zip ready to flash.
#
# Requirements:
#   - Android NDK r25+ (set ANDROID_NDK_HOME or place it at /opt/android-ndk)
#
set -euo pipefail

cd "$(dirname "$0")"                # module root
MODULE_DIR="$(pwd)"
OUT_DIR="$MODULE_DIR/out"
ZIP_NAME="HideAllRoot.zip"

NDK="${ANDROID_NDK_HOME:-/opt/android-ndk}"
if [ ! -x "$NDK/ndk-build" ]; then
    echo "ERROR: ndk-build not found. Set ANDROID_NDK_HOME or install NDK at /opt/android-ndk" >&2
    exit 1
fi

echo "[*] NDK: $NDK"
echo "[*] Cleaning previous build ..."
rm -rf "$OUT_DIR" "$MODULE_DIR/libs" "$MODULE_DIR/obj"
mkdir -p "$OUT_DIR"

echo "[*] Compiling libzygisk.so (arm64-v8a, armeabi-v7a) ..."
"$NDK/ndk-build" NDK_PROJECT_PATH="$MODULE_DIR" \
    APP_BUILD_SCRIPT="$MODULE_DIR/jni/Android.mk" \
    NDK_APPLICATION_MK="$MODULE_DIR/jni/Application.mk" \
    NDK_LIBS_OUT="$OUT_DIR/libs" \
    NDK_OUT="$OUT_DIR/obj"

echo "[*] Placing binaries ..."
for abi in arm64-v8a armeabi-v7a; do
    case "$abi" in
        arm64-v8a) dst="zygisk/arm64" ;;
        armeabi-v7a) dst="zygisk/arm" ;;
    esac
    mkdir -p "$MODULE_DIR/$dst"
    cp -f "$OUT_DIR/libs/$abi/libzygisk.so" "$MODULE_DIR/$dst/libzygisk.so"
    echo "    -> $dst/libzygisk.so"
done

echo "[*] Packaging $ZIP_NAME ..."
rm -f "$MODULE_DIR/$ZIP_NAME"
( cd "$MODULE_DIR" && zip -r -q "../$ZIP_NAME" . \
    -x 'jni/*' -x 'out/*' -x 'libs/*' -x 'obj/*' -x '.git/*' -x '*.zip' \
       -x 'build.sh' -x 'README.md' -x '.clang-format' -x '.github/*' )
mv "$MODULE_DIR/../$ZIP_NAME" "$MODULE_DIR/$ZIP_NAME"

echo "[*] Done -> $MODULE_DIR/$ZIP_NAME"
ls -lh "$MODULE_DIR/$ZIP_NAME"
