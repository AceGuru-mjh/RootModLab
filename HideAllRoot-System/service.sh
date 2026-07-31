#!/system/bin/sh
# HideAllRoot-System: service 阶段
# 时机：系统完全启动后。负责 resetprop 属性伪装与日志/痕迹清理。

MODDIR=${0%/*}
CONF_DIR="/data/adb/hideallroot"

. "$MODDIR/config/default.conf" 2>/dev/null

[ "$ENABLE" = "0" ] && exit 0
[ "$ENABLE_PROP_SPOOF" = "1" ] || exit 0

# 等待系统启动完成
while [ "$(getprop sys.boot_completed)" != "1" ]; do
    sleep 1
done

# ═══════════════════════════════════════════════════════
# 1. 属性伪装（resetprop）
#    这些属性会被 Momo / Ruru 通过 __system_property_get 读取
# ═══════════════════════════════════════════════════════
resetprop -n ro.debuggable 0
resetprop -n ro.secure 1
resetprop -n ro.build.selinux enforcing

# Play Integrity / 强机检需要的 bootloader 状态
resetprop -n ro.boot.verifiedbootstate green
resetprop -n ro.boot.flash.locked 1
resetprop -n ro.boot.veritymode enforcing
resetprop -n ro.boot.vbmeta.device_state locked

# 清除 Magisk 相关属性（不影响已经运行的服务）
resetprop --delete ro.magisk.version 2>/dev/null
resetprop --delete init.svc.magiskd 2>/dev/null
resetprop --delete init.svc.zygiskd 2>/dev/null

# ═══════════════════════════════════════════════════════
# 2. 痕迹清理
# ═══════════════════════════════════════════════════════
logcat -c 2>/dev/null
rm -rf /data/local/tmp/*.so 2>/dev/null

echo "[HideAllRoot-System] service done" >> "$CONF_DIR/system_status"
