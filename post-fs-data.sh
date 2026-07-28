#!/system/bin/sh
# ============================================================================
# HideAllRoot v2.0 开机早期脚本 (post-fs-data.sh)
# ----------------------------------------------------------------------------
# 职责（静态、全局、安全）:
#   * 重置危险系统属性 (ro.debuggable / ro.secure / ro.build.tags ...)
#   * 清理 Magisk 日志文件痕迹
#   * 防砖: 检测到 /data/local/tmp/disable_hideallroot 时自动禁用本模块
#
# 注意: 应用层 / 进程层的深度隐藏由 Zygisk 注入完成（含 VFS 级卸载）。
# ============================================================================

MODDIR=${0%/*}
MODID=hideallroot
CONFIG_DIR=/data/adb/$MODID
CONFIG=$CONFIG_DIR/config.conf

# 读取开关（带默认值）。对取值做白名单净化，剔除换行/注入字符，仅保留安全字符。
cfg() {
    v=$(grep -i "^$1=" "$CONFIG" 2>/dev/null | tail -n1 | cut -d= -f2-)
    echo "$v" | tr -d '[:space:]' | tr -cd '0-9a-zA-Z_,.-'
}
ENABLE=$(cfg ENABLE);          [ -z "$ENABLE" ] && ENABLE=0
FILE_HIDE=$(cfg ENABLE_FILE_HIDE);   case "$FILE_HIDE" in 0|1) ;; *) FILE_HIDE=1 ;; esac
PROP_HIDE=$(cfg ENABLE_PROP_HIDE);   case "$PROP_HIDE" in 0|1) ;; *) PROP_HIDE=1 ;; esac
[ "$ENABLE" = "0" ] && { FILE_HIDE=0; PROP_HIDE=0; }

# ---- 防砖机制 --------------------------------------------------------------
if [ -f /data/local/tmp/disable_hideallroot ]; then
    ui_print "[HideAllRoot] 检测到禁用标记，自动停用模块" 2>/dev/null || true
    touch "$MODDIR/disable" 2>/dev/null || true
fi

# ---- 1. 危险属性重置 -------------------------------------------------------
if [ "$PROP_HIDE" = "1" ]; then
    resetprop ro.debuggable 0          2>/dev/null
    resetprop ro.secure 1              2>/dev/null
    resetprop ro.build.type user       2>/dev/null
    resetprop ro.build.tags release-keys 2>/dev/null
    resetprop --delete ro.magisk.version 2>/dev/null
    resetprop --delete init.svc.magiskd 2>/dev/null
    resetprop --delete init.svc.zygiskd 2>/dev/null
    resetprop persist.sys.root 0        2>/dev/null
fi

# ---- 2. 日志文件痕迹屏蔽（仅对真实存在的文件 bind /dev/null）-------------
if [ "$FILE_HIDE" = "1" ]; then
    for f in /cache/magisk.log /data/adb/magisk.log /data/adb/magisk_debug.log; do
        if [ -f "$f" ]; then
            mount -o bind /dev/null "$f" 2>/dev/null
        fi
    done
fi

exit 0
