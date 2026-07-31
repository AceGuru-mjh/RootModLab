#!/system/bin/sh
# HideAllRoot-Runtime: 安装脚本
# 双模块之一（Zygisk 运行时）。编译产物 libzygisk.so 由 build.sh 放入本目录 zygisk/<abi>/。
MODDIR=${0%/*}
CONFIG_DIR=/data/adb/hideallroot

ui_print() { echo "$1"; }

# ── 依赖检查：必须先安装 HideAllRoot-System ──
if [ ! -d "/data/adb/modules/hideallroot_system" ]; then
    ui_print "❌ ERROR: HideAllRoot-System 未安装！"
    ui_print "   请先安装 HideAllRoot-System 模块。"
    abort "   Runtime 安装中止。"
fi

ui_print "HideAllRoot-Runtime: 安装完成"
ui_print "  与 HideAllRoot-System 协同工作"
ui_print "  seccomp PoC 默认关闭，需在 config/default.conf 开启 ENABLE_SECCOMP_POC=1"

# 初始化共享配置（首次安装写入默认配置，供 action.sh / WebUI 编辑）
mkdir -p "$CONFIG_DIR"
if [ ! -f "$CONFIG_DIR/config.conf" ]; then
    cp -f "$MODDIR/config/default.conf" "$CONFIG_DIR/config.conf" 2>/dev/null || true
    chmod 0644 "$CONFIG_DIR/config.conf" 2>/dev/null || true
fi
