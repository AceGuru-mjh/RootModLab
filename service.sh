#!/system/bin/sh
# HideAllRoot v2.0 service.sh
# 不写入任何日志文件

MODDIR=${0%/*}
MODID=hideallroot
CONFIG_DIR=/data/adb/$MODID

wait_boot() {
    while [ "$(getprop sys.boot_completed)" != "1" ]; do
        sleep 2
    done
}

cfg() {
    v=$(grep -i "^$1=" "$CONFIG_DIR/config.conf" 2>/dev/null | tail -n1 | cut -d= -f2-)
    echo "$v" | tr -d '[:space:]' | tr -cd '0-9a-zA-Z_,.-'
}

mkdir -p "$CONFIG_DIR" 2>/dev/null
wait_boot

# 修复：正确读取 ENABLE 总开关
ENABLE=$(cfg ENABLE); [ -z "$ENABLE" ] && ENABLE=1
PROP_HIDE=$(cfg ENABLE_PROP_HIDE); case "$PROP_HIDE" in 0|1) ;; *) PROP_HIDE=1 ;; esac

if [ "$ENABLE" = "1" ] && [ "$PROP_HIDE" = "1" ]; then
    resetprop ro.debuggable 0 2>/dev/null
    resetprop ro.secure 1 2>/dev/null
fi

exit 0
