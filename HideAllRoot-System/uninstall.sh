#!/system/bin/sh
# HideAllRoot-System: 卸载脚本
# 卸载时清理运行时共享目录（仅本模块写入的标志文件，不删 Runtime 的配置）
rm -f /data/adb/hideallroot/system_status 2>/dev/null
echo "HideAllRoot-System uninstalled"
