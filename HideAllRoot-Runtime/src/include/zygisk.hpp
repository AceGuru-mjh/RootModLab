// ============================================================================
// PLACEHOLDER — 必须由构建时填充
// ============================================================================
//
// 本文件是 Magisk Zygisk API 头文件的占位符。实际构建前，请从 Magisk 官方仓库
// 下载真实头文件并覆盖本文件：
//
//   Magisk:  https://github.com/topjohnwu/Magisk/blob/master/native/src/external/zygisk.hpp
//   KernelSU: https://github.com/tiann/KernelSU/blob/main/kernel/zygisk/zygisk.hpp
//
// 当前 har_runtime.cpp 依赖该头文件中的：
//   - namespace zygisk { class ModuleBase; class Api; ... }
//   - REGISTER_ZYGISK_MODULE 宏
//   - zygisk::AppSpecializeArgs / ServerSpecializeArgs
//   - zygisk::DLCLOSE_MODULE_LIBRARY / FORCE_UNMOUNT 选项
//
// 注意：在没有真实 zygisk.hpp 的情况下，src/ 下的代码无法编译。
// 另外：Magisk 的 Zygisk 加载器只加载 `zygisk/<abi>/libzygisk.so`，
// CMakeLists.txt 当前产出的 libhar_runtime.so 需要更名为 libzygisk.so 才会被加载。
// ============================================================================
