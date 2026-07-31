# HideAllRoot-System

双模块架构之**系统级**模块（`id=hideallroot_system`）。

- 在 boot 早期（`post-fs-data.sh`）准备干净的挂载视图：卸载 Magisk tmpfs / overlay 覆盖（保留 `/data/adb`），清理安装痕迹。
- 系统完全启动后（`service.sh`）用 `resetprop` 伪装 `ro.debuggable` / `ro.secure` / `ro.boot.verifiedbootstate` 等属性，并删除 Magisk 相关属性。
- 极简 `sepolicy.rule`：仅放行 Zygote / 应用进程在自身命名空间 `umount` tmpfs / overlay。
- 必须**先于 HideAllRoot-Runtime** 安装。
- 配置：`config/default.conf`（`ENABLE_PROP_SPOOF` / `ENABLE_MOUNT_CLEAN` / `ENABLE_TRACE_CLEAN`）。

纯 shell 模块，无需编译，直接由顶层 `build.sh` 打包为 `HideAllRoot-System.zip`。
