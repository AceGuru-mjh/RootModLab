#!/system/bin/sh
# ============================================================================
# HideAllRoot v2.0 安装脚本 (customize.sh)
# 运行环境: Magisk / KernelSU / APatch 安装框架
# ----------------------------------------------------------------------------
# 职责:
#   1. 识别当前 Root 框架 (Magisk / KSU / APatch)
#   2. 创建 /data/adb/hideallroot 配置目录并写入默认配置
#   3. 在 Magisk 环境下把检测工具加入 DenyList 作为兜底（不强制，由本模块接管）
# ============================================================================

MODID=hideallroot
CONFIG_DIR=/data/adb/$MODID

ui_print "- 正在安装 HideAllRoot v2.0 一体化隐藏模块 ..."

# ---- 1. 框架识别 ----------------------------------------------------------
if [ -n "$KSU" ]; then
    ui_print "- 框架: KernelSU ($KSU_VER / $KSU_VER_CODE)"
elif [ -n "$APATCH" ]; then
    ui_print "- 框架: APatch ($APATCH_VER / $APATCH_VER_CODE)"
else
    ui_print "- 框架: Magisk ($MAGISK_VER / $MAGISK_VER_CODE)"
fi

# ---- 2. 配置目录与默认配置 ------------------------------------------------
ui_print "- 初始化配置目录 $CONFIG_DIR"
mkdir -p "$CONFIG_DIR"
if [ ! -f "$CONFIG_DIR/config.conf" ]; then
    cp -f "$MODPATH/config/default.conf" "$CONFIG_DIR/config.conf" 2>/dev/null || true
fi
chown root:root "$CONFIG_DIR/config.conf" 2>/dev/null || true
chmod 0644 "$CONFIG_DIR/config.conf" 2>/dev/null || true

# ---- 3. DenyList 兜底（仅 Magisk）----------------------------------------
# 关闭“强制 DenyList”，把检测工具加入列表但不强制隔离，
# 真正的隐藏交给本模块的 Zygisk 注入完成（由模块接管）。
if [ -z "$KSU" ] && [ -z "$APATCH" ] && command -v magisk >/dev/null 2>&1; then
    magisk settings set enforce_denylist false 2>/dev/null || true
    for pkg in com.xtremelabs.momo com.springroot.ruru com.chunqiu.check; do
        magisk --denylist add "$pkg" 2>/dev/null || true
    done
    ui_print "- 已将检测工具加入 DenyList（未强制，由模块接管隐藏）"
fi

# KSU / APatch 需要 ZygiskNext 才能让本模块的 zygisk/ 库加载
if [ -n "$KSU" ] || [ -n "$APATCH" ]; then
    ui_print "- 提示: KernelSU / APatch 需额外安装 ZygiskNext 模块后本模块才会生效"
fi

ui_print "- 安装完成，请重启设备使 Zygisk 注入生效"
