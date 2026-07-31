#!/system/bin/sh
# HideAllRoot-System: 安装脚本
# 双模块之一（系统级）。与 HideAllRoot-Runtime 配合，可独立启用。

MODDIR=${0%/*}

# Magisk 模块约定：最后一行 touch 一个 flag 表示安装成功
# 无需额外动作，配置文件已由模块目录自带。

ui_print() { echo "$1"; }

ui_print "HideAllRoot-System: 安装完成"
ui_print "  与 HideAllRoot-Runtime(Zygisk) 协同工作"
ui_print "  配置: $MODDIR/config/default.conf"

# 确保运行时共享目录存在（Runtime 模块也会写入）
mkdir -p /data/adb/hideallroot
