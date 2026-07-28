#!/system/bin/sh
# ============================================================================
# HideAllRoot 终端配置菜单 (action.sh)
# 在 Magisk / KSU / APatch 管理器中点击模块“操作”即可运行。
# 提供无图形环境下的快捷开关（每个模块都要有 UI，终端菜单即为其一）。
# ============================================================================

MODID=hideallroot
CONFIG_DIR=/data/adb/$MODID
CONFIG=$CONFIG_DIR/config.conf

cfg() { grep -i "^$1=" "$CONFIG" 2>/dev/null | tail -n1 | cut -d= -f2- ; }
set_cfg() {
    # $1=key $2=value
    if grep -qi "^$1=" "$CONFIG" 2>/dev/null; then
        sed -i "s|^$1=.*|$1=$2|" "$CONFIG"
    else
        echo "$1=$2" >> "$CONFIG"
    fi
}

render() {
    clear
    echo "=============================================="
    echo "        HideAllRoot 终端配置菜单"
    echo "=============================================="
    echo " 1. 文件层隐藏      : $([ "$(cfg ENABLE_FILE_HIDE)" = 1 ] && echo 开 || echo 关)"
    echo " 2. 属性隐藏        : $([ "$(cfg ENABLE_PROP_HIDE)" = 1 ] && echo 开 || echo 关)"
    echo " 3. Zygisk 原生Hook : $([ "$(cfg ENABLE_NATIVE_HOOK)" = 1 ] && echo 开 || echo 关)"
    echo " 4. 应用列表隐藏    : $([ "$(cfg ENABLE_APPLIST_HIDE)" = 1 ] && echo 开 || echo 关)"
    echo " 5. 进程隐藏        : $([ "$(cfg ENABLE_PROC_HIDE)" = 1 ] && echo 开 || echo 关)"
    echo " 6. 反调试(ptrace)  : $([ "$(cfg ENABLE_ANTIDEBUG)" = 1 ] && echo 开 || echo 关)"
    echo " 7. Play Integrity  : $([ "$(cfg ENABLE_PI_FIX)" = 1 ] && echo 开 || echo 关)"
    echo " 8. 目标模式        : $([ "$(cfg TARGET_MODE)" = 0 ] && echo 全部应用 || ([ "$(cfg TARGET_MODE)" = 1 ] && echo 仅检测工具 || echo 仅自定义))"
    echo " 9. 模块启停        : $([ -f /data/adb/modules/$MODID/disable ] && echo 已禁用 || echo 已启用)"
    echo "----------------------------------------------"
    echo " a. 应用配置(重启zygote相关进程生效)"
    echo " r. 重启设备"
    echo " q. 退出"
    echo "=============================================="
}

toggle() {
    v=$(cfg "$1")
    if [ "$v" = "1" ]; then set_cfg "$1" 0; else set_cfg "$1" 1; fi
}

while true; do
    render
    printf "请选择 [1-9/a/r/q]: "
    read -r choice
    case "$choice" in
        1) toggle ENABLE_FILE_HIDE ;;
        2) toggle ENABLE_PROP_HIDE ;;
        3) toggle ENABLE_NATIVE_HOOK ;;
        4) toggle ENABLE_APPLIST_HIDE ;;
        5) toggle ENABLE_PROC_HIDE ;;
        6) toggle ENABLE_ANTIDEBUG ;;
        7) toggle ENABLE_PI_FIX ;;
        8) m=$(cfg TARGET_MODE); m=$(( (m+1) % 3 )); set_cfg TARGET_MODE $m ;;
        9) if [ -f /data/adb/modules/$MODID/disable ]; then rm -f /data/adb/modules/$MODID/disable; echo "已启用"; else touch /data/adb/modules/$MODID/disable; echo "已禁用"; fi ;;
        a) echo "配置已保存，新启动的应用立即生效。"; sleep 1 ;;
        r) echo "即将重启..."; sleep 1; reboot ;;
        q) echo "再见"; exit 0 ;;
        *) echo "无效选项"; sleep 1 ;;
    esac
done
