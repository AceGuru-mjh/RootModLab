#pragma once

#include <android/log.h>
#include <cstdio>
#include <cstdarg>

#define HAR_TAG "HideAllRoot"

// 日志级别控制（编译时）
#ifndef HAR_LOG_LEVEL
#define HAR_LOG_LEVEL 2  // 0=OFF, 1=ERROR, 2=WARN, 3=INFO, 4=DEBUG, 5=VERBOSE
#endif

namespace har::log {

enum Level : int {
    OFF     = 0,
    ERROR   = 1,
    WARN    = 2,
    INFO    = 3,
    DEBUG   = 4,
    VERBOSE = 5,
};

inline void write(Level level, const char* fmt, ...) {
    if (level > HAR_LOG_LEVEL) return;

    int prio;
    switch (level) {
        case ERROR:   prio = ANDROID_LOG_ERROR; break;
        case WARN:    prio = ANDROID_LOG_WARN;  break;
        case INFO:    prio = ANDROID_LOG_INFO;  break;
        case DEBUG:   prio = ANDROID_LOG_DEBUG; break;
        default:      prio = ANDROID_LOG_VERBOSE; break;
    }

    va_list args;
    va_start(args, fmt);
    __android_log_vprint(prio, HAR_TAG, fmt, args);
    va_end(args);
}

// 文件日志（写入 /data/adb/hideallroot/log/）
void write_file(Level level, const char* fmt, ...);
void init_file_log(const char* pkg_name);
void close_file_log();

} // namespace har::log

#define LOG_E(...) har::log::write(har::log::ERROR,   __VA_ARGS__)
#define LOG_W(...) har::log::write(har::log::WARN,    __VA_ARGS__)
#define LOG_I(...) har::log::write(har::log::INFO,    __VA_ARGS__)
#define LOG_D(...) har::log::write(har::log::DEBUG,   __VA_ARGS__)
#define LOG_V(...) har::log::write(har::log::VERBOSE, __VA_ARGS__)
