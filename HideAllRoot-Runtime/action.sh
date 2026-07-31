#!/system/bin/sh
# ============================================================================
# HideAllRoot v2.0 终端配置菜单 (action.sh)
# 在 Magisk / KSU / APatch 管理器中点击模块“操作”即可运行。
# 提供无图形环境下的快捷开关（每个模块都要有 UI，终端菜单即为其一）。
# ============================================================================

MODID=hideallroot
CONFIG_DIR=/data/adb/$MODID
CONFIG=$CONFIG_DIR/config.conf

cfg() { grep -i "^$1=" "$CONFIG" 2>/dev/null | tail -n1 | cut -d= -f2- ; }
set_cfg() {
    if grep -qi "^$1=" "$CONFIG" 2>/dev/null; then
        sed -i "s|^$1=.*|$1=$2|" "$CONFIG"
    else
        echo "$1=$2" >> "$CONFIG"
    fi
}

render() {
    clear
    echo "=============================================="
    echo "        HideAllRoot v2.0 终端配置菜单"
    echo "=============================================="
    echo " 1. 总开关 ENABLE        : $([ "$(cfg ENABLE)" = 1 ] && echo 开 || echo 关)"
    echo " 2. 文件层隐藏           : $([ "$(cfg ENABLE_FILE_HIDE)" = 1 ] && echo 开 || echo 关)"
    echo " 3. 属性隐藏             : $([ "$(cfg ENABLE_PROP_HIDE)" = 1 ] && echo 开 || echo 关)"
    echo " 4. 原生 Hook 防护       : $([ "$(cfg ENABLE_NATIVE_HOOK)" = 1 ] && echo 开 || echo 关)"
    echo " 5. 应用列表隐藏         : $([ "$(cfg ENABLE_APPLIST_HIDE)" = 1 ] && echo 开 || echo 关)"
    echo " 6. 进程隐藏             : $([ "$(cfg ENABLE_PROC_HIDE)" = 1 ] && echo 开 || echo 关)"
    echo " 7. 反调试               : $([ "$(cfg ENABLE_ANTIDEBUG)" = 1 ] && echo 开 || echo 关)"
    echo " 8. PI 修复              : $([ "$(cfg ENABLE_PI_FIX)" = 1 ] && echo 开 || echo 关)"
    echo " 9. 挂载点隐藏           : $([ "$(cfg ENABLE_MOUNT_HIDE)" = 1 ] && echo 开 || echo 关)"
    echo " a. dladdr 隐藏          : $([ "$(cfg ENABLE_DLADDR_HIDE)" = 1 ] && echo 开 || echo 关)"
    echo " b. VFS 卸载             : $([ "$(cfg ENABLE_UNMOUNT)" = 1 ] && echo 开 || echo 关)"
    echo " c. 环境变量清洗         : $([ "$(cfg ENABLE_ENV_CLEAN)" = 1 ] && echo 开 || echo 关)"
    echo " d. Zygisk 痕迹清理      : $([ "$(cfg ENABLE_ZYGISK_CLEAN)" = 1 ] && echo 开 || echo 关)"
    echo " e. 目标模式             : $([ "$(cfg TARGET_MODE)" = 0 ] && echo 全部应用 || ([ "$(cfg TARGET_MODE)" = 1 ] && echo 仅检测工具 || echo 仅自定义))"
    echo " f. 模块启停             : $([ -f /data/adb/modules/$MODID/disable ] && echo 已禁用 || echo 已启用)"
    echo "----------------------------------------------"
    echo " s. 保存并应用(重启 zygote 相关进程生效)"
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
    printf "请选择 [1-f/s/r/q]: "
    read -r choice
    case "$choice" in
        1) toggle ENABLE ;;
        2) toggle ENABLE_FILE_HIDE ;;
        3) toggle ENABLE_PROP_HIDE ;;
        4) toggle ENABLE_NATIVE_HOOK ;;
        5) toggle ENABLE_APPLIST_HIDE ;;
        6) toggle ENABLE_PROC_HIDE ;;
        7) toggle ENABLE_ANTIDEBUG ;;
        8) toggle ENABLE_PI_FIX ;;
        9) toggle ENABLE_MOUNT_HIDE ;;
        a) toggle ENABLE_DLADDR_HIDE ;;
        b) toggle ENABLE_UNMOUNT ;;
        c) toggle ENABLE_ENV_CLEAN ;;
        d) toggle ENABLE_ZYGISK_CLEAN ;;
        e) m=$(cfg TARGET_MODE); m=$(( (m+1) % 3 )); set_cfg TARGET_MODE $m ;;
        f) if [ -f /data/adb/modules/$MODID/disable ]; then rm -f /data/adb/modules/$MODID/disable; echo "已启用"; else touch /data/adb/modules/$MODID/disable; echo "已禁用"; fi ;;
        s) echo "配置已保存，新启动的应用立即生效。"; sleep 1 ;;
        r) echo "即将重启..."; sleep 1; reboot ;;
        q) echo "再见"; exit 0 ;;
        *) echo "无效选项"; sleep 1 ;;
    esac
done
