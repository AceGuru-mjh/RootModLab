// ═══════════════════════════════════════════════════════════
// HideAllRoot Runtime: Zygisk 模块主入口
// ═══════════════════════════════════════════════════════════

#include "include/logging.h"
#include "include/path_filter.h"
#include "include/seccomp_engine.h"
#include "include/linker_cleaner.h"
#include "include/proc_hider.h"
#include "include/timing_guard.h"
#include "include/fd_tracker.h"

#include "zygisk.hpp"

#include <jni.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <sys/mount.h>

using namespace har;

// ═══════════════════════════════════════════════════════════
// 全局状态
// ═══════════════════════════════════════════════════════════

static std::string g_current_package;
static bool g_should_hide = false;

// ═══════════════════════════════════════════════════════════
// VFS 卸载（保留原有逻辑）
// ═══════════════════════════════════════════════════════════

static void PerformVfsUnmount() {
    // 在 app 的私有 mount namespace 中卸载 Magisk 挂载
    // Zygisk 的 FORCE_UNMOUNT 选项已经做了大部分工作
    // 这里补充卸载可能遗漏的挂载点

    const char* mount_points[] = {
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/data/adb/magisk",
        "/debug_ramdisk",
        nullptr
    };

    for (int i = 0; mount_points[i]; i++) {
        // 尝试卸载（失败也无所谓，可能本来就没挂载）
        umount2(mount_points[i], MNT_DETACH);
    }
}

// ═══════════════════════════════════════════════════════════
// 环境变量清洗
// ═══════════════════════════════════════════════════════════

static void CleanEnvironment() {
    unsetenv("LD_PRELOAD");
    unsetenv("LD_LIBRARY_PATH");
    unsetenv("LD_DEBUG");
    unsetenv("MAGISK_VER");
    unsetenv("MAGISK_VER_CODE");
}

// ═══════════════════════════════════════════════════════════
// Zygisk 模块类
// ═══════════════════════════════════════════════════════════

class HideAllRootModule : public zygisk::ModuleBase {
public:

    void onLoad(zygisk::Api* api, JNIEnv* env) override {
        m_api = api;
        m_env = env;

        // 加载配置和路径规则
        PathFilter::LoadRules("/data/adb/hideallroot/config.conf");

        LOG_I("=== HideAllRoot Runtime v2.1.0 loaded ===");
        LOG_I("API level: %d, PID: %d", PathFilter::GetApiLevel(), getpid());
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs* args) override {
        // ─── 获取包名 ───
        const char* pkg = nullptr;
        if (args->nice_name) {
            pkg = m_env->GetStringUTFChars(args->nice_name, nullptr);
        }

        if (!pkg || !pkg[0]) {
            // 非 app 进程（如 zygote 自身），跳过
            if (pkg) m_env->ReleaseStringUTFChars(args->nice_name, pkg);
            m_api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        g_current_package = pkg;
        m_env->ReleaseStringUTFChars(args->nice_name, pkg);

        // ─── 判断是否需要隐藏 ───
        g_should_hide = PathFilter::ShouldHidePackage(g_current_package.c_str());

        if (!g_should_hide) {
            LOG_D("preAppSpecialize: %s → not in target list, skipping",
                  g_current_package.c_str());
            m_api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        LOG_I("preAppSpecialize: %s → HIDING", g_current_package.c_str());

        // ─── 初始化文件日志 ───
        log::init_file_log(g_current_package.c_str());

        // ─── Step 1: VFS 卸载 ───
        // 使用 Zygisk 内置的 FORCE_UNMOUNT
        m_api->setOption(zygisk::FORCE_UNMOUNT);
        // 补充手动卸载
        PerformVfsUnmount();

        // ─── Step 2: 环境变量清洗 ───
        CleanEnvironment();

        // ─── Step 3: 初始化进程隐藏器 ───
        ProcHider::Init();

        // ─── Step 4: 安装 seccomp 过滤器（核心）───
        // 这必须在任何 app 代码执行前完成
        if (!SeccompEngine::Install()) {
            LOG_E("FATAL: seccomp installation failed for %s",
                  g_current_package.c_str());
            // 降级：不安装 seccomp，但其他隐藏仍然生效
        }

        // ─── Step 5: 初始化时序防护 ───
        TimingGuard::Init();

        LOG_I("preAppSpecialize: %s → all hooks installed",
              g_current_package.c_str());
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs* args) override {
        if (!g_should_hide) return;

        LOG_I("postAppSpecialize: %s → cleaning traces",
              g_current_package.c_str());

        // ─── Step 6: Linker 清洗（对抗 "找到 Zygisk"）───
        LinkerCleaner::Clean();

        // ─── Step 7: 刷新进程隐藏缓存 ───
        ProcHider::Refresh();

        // ─── Step 8: 输出统计 ───
        auto stats = SeccompEngine::GetStats();
        LOG_I("postAppSpecialize: %s → seccomp stats: "
              "intercepted=%llu blocked=%llu allowed=%llu",
              g_current_package.c_str(),
              (unsigned long long)stats.total_intercepted,
              (unsigned long long)stats.total_blocked,
              (unsigned long long)stats.total_allowed);

        LOG_I("postAppSpecialize: %s → linker cleaned %d libs",
              g_current_package.c_str(), LinkerCleaner::GetCleanedCount());

        // ─── Step 9: 关闭文件日志 ───
        log::write_file(log::INFO, "=== HideAllRoot active for %s ===",
                        g_current_package.c_str());
        log::close_file_log();
    }

    // 可选：拦截 native 方法
    void preServerSpecialize(zygisk::ServerSpecializeArgs* args) override {
        // 对 app zygote / isolated process 也生效
        // Momo 使用 isolated process 做交叉验证
        // 这里同样安装 seccomp
        LOG_I("preServerSpecialize: applying to server process");

        ProcHider::Init();
        SeccompEngine::Install();
        TimingGuard::Init();
    }

private:
    zygisk::Api* m_api = nullptr;
    JNIEnv* m_env = nullptr;
};

// ═══════════════════════════════════════════════════════════
// 注册
// ═══════════════════════════════════════════════════════════

REGISTER_ZYGISK_MODULE(HideAllRootModule)
