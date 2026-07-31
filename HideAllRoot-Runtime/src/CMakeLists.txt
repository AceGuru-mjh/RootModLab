cmake_minimum_required(VERSION 3.18)
project(har_runtime CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ─── Android NDK 配置 ───
if(NOT ANDROID)
    message(FATAL_ERROR "This project must be built with Android NDK toolchain")
endif()

# ─── 源文件 ───
add_library(har_runtime SHARED
    har_runtime.cpp
    seccomp_engine.cpp
    linker_cleaner.cpp
    path_filter.cpp
    proc_hider.cpp
    timing_guard.cpp
    fd_tracker.cpp
    logging.cpp
)

# ─── 头文件搜索路径 ───
target_include_directories(har_runtime PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# ─── 编译选项 ───
target_compile_options(har_runtime PRIVATE
    -Wall -Wextra -Werror
    -fvisibility=hidden          # 默认隐藏所有符号
    -fvisibility-inlines-hidden
    -ffunction-sections          # 允许 linker 移除未使用函数
    -fdata-sections
    -fno-exceptions              # 减小体积
    -fno-rtti
    -O2                          # 性能（seccomp handler 在热路径上）
    -fno-stack-protector         # 避免 stack canary 干扰 SIGSYS handler
)

# ─── 链接选项 ───
target_link_options(har_runtime PRIVATE
    -Wl,--gc-sections            # 移除未使用的 section
    -Wl,--exclude-libs,ALL       # 不导出静态库符号
    -Wl,-soname,libhar_runtime.so
    -s                           # strip
)

# ─── 链接库 ───
target_link_libraries(har_runtime
    log       # Android logging
    dl        # dlopen/dlsym
)

# ─── 输出路径 ───
set_target_properties(har_runtime PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../zygisk/${ANDROID_ABI}
)
