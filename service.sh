#!/system/bin/sh
# ============================================================================
# HideAllRoot 开机晚期脚本 (service.sh)
# ----------------------------------------------------------------------------
# 在系统启动完成后运行，负责:
#   * 确保配置目录存在
#   * 二次校正关键属性（部分 ROM 会在 boot 完成后改写 ro.* 调试属性）
#   * 记录模块加载日志，便于排查
# ============================================================================

MODDIR=${0%/*}
MODID=hideallroot
CONFIG_DIR=/data/adb/$MODID

wait_boot() {
    while [ "$(getprop sys.boot_completed)" != "1" ]; do
        sleep 2
    done
}

# 仅在配置允许时做属性二次校正
cfg() { grep -i "^$1=" "$CONFIG_DIR/config.conf" 2>/dev/null | tail -n1 | cut -d= -f2- ; }

mkdir -p "$CONFIG_DIR" 2>/dev/null

wait_boot

# 注意：本脚本【绝不】写入任何可被检测工具 access() 发现的日志文件
#（审查报告 1.7 点名 /data/local/tmp/hideallroot.log 是明确 root 痕迹）。
PROP_HIDE=$(cfg ENABLE_PROP_HIDE); [ -z "$PROP_HIDE" ] && PROP_HIDE=1
if [ "$PROP_HIDE" = "1" ]; then
    resetprop ro.debuggable 0 2>/dev/null
    resetprop ro.secure 1 2>/dev/null
fi

exit 0
