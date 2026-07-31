#!/system/bin/sh
# HideAllRoot-System: post-fs-data 阶段
# 时机：/data 已挂载、Zygote 尚未启动。负责早期 mount 视图准备与痕迹清理。

MODDIR=${0%/*}
CONF_DIR="/data/adb/hideallroot"
mkdir -p "$CONF_DIR"

. "$MODDIR/config/default.conf" 2>/dev/null

[ "$ENABLE" = "0" ] && exit 0

# ═══════════════════════════════════════════════════════
# 1. mount 视图清理（在 Zygote fork 前准备好干净视图）
#    仅卸载 magisk 的 tmpfs 覆盖，保留 /data/adb 本身（否则模块失效）
# ═══════════════════════════════════════════════════════
if [ "$ENABLE_MOUNT_CLEAN" = "1" ]; then
    for mnt in $(mount | grep -E "magisk|modules" | awk '{print $3}'); do
        case "$mnt" in
            /data/adb/modules) : ;;        # 保留模块目录
            /data/adb/modules_update) : ;; # 保留
            *) umount -l "$mnt" 2>/dev/null ;;
        esac
    done
fi

# ═══════════════════════════════════════════════════════
# 2. 安装痕迹清理
# ═══════════════════════════════════════════════════════
if [ "$ENABLE_TRACE_CLEAN" = "1" ]; then
    rm -rf /cache/magisk* 2>/dev/null
    rm -rf /data/cache/magisk* 2>/dev/null
    rm -f /data/local/tmp/magisk* 2>/dev/null
    rm -f /data/local/tmp/.magisk* 2>/dev/null
fi

echo "[HideAllRoot-System] post-fs-data done" > "$CONF_DIR/system_status"
