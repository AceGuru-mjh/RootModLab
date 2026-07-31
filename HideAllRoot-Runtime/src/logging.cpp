#include "include/logging.h"
#include <cstdio>
#include <cstring>
#include <ctime>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

namespace har::log {

static int g_log_fd = -1;
static char g_log_path[256] = {0};

void init_file_log(const char* pkg_name) {
    // 日志目录
    const char* dir = "/data/adb/hideallroot/log";
    mkdir(dir, 0700);

    // 文件名：包名_时间戳.log
    time_t now = time(nullptr);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);

    snprintf(g_log_path, sizeof(g_log_path),
             "%s/%s_%04d%02d%02d_%02d%02d%02d.log",
             dir, pkg_name,
             tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
             tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec);

    g_log_fd = open(g_log_path, O_WRONLY | O_CREAT | O_APPEND, 0600);
}

void close_file_log() {
    if (g_log_fd >= 0) {
        close(g_log_fd);
        g_log_fd = -1;
    }
}

void write_file(Level level, const char* fmt, ...) {
    if (g_log_fd < 0) return;

    static const char* level_str[] = {"OFF", "E", "W", "I", "D", "V"};

    time_t now = time(nullptr);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);

    char header[64];
    int hlen = snprintf(header, sizeof(header),
                        "[%02d:%02d:%02d][%s][%d] ",
                        tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec,
                        level_str[level], getpid());

    char body[1024];
    va_list args;
    va_start(args, fmt);
    int blen = vsnprintf(body, sizeof(body), fmt, args);
    va_end(args);

    // 写入（原子性尽量保证）
    write(g_log_fd, header, hlen);
    write(g_log_fd, body, blen);
    write(g_log_fd, "\n", 1);
}

} // namespace har::log
