#include "include/linker_cleaner.h"
#include "include/path_filter.h"
#include "include/logging.h"

#include <dlfcn.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/system_properties.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <string>

#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#define PR_SET_VMA_ANON_NAME 0
#endif

namespace har {

static int g_cleaned_count = 0;

// 需要隐藏的库名模式
static const char* kHiddenPatterns[] = {
    "libzygisk",
    "libriru",
    "libmagisk",
    "libhar_runtime",
    "liblsposed",
    "libxposed",
    "libsandhook",
    "libpine",
};

static bool IsHiddenLib(const char* name) {
    if (!name) return false;
    for (const char* pat : kHiddenPatterns) {
        if (strstr(name, pat)) return true;
    }
    return false;
}

// ═══════════════════════════════════════════════════════════
// 公开接口
// ═══════════════════════════════════════════════════════════

bool LinkerCleaner::Clean() {
    LOG_I("LinkerCleaner: starting full clean (pid=%d)", getpid());

    bool ok = true;
    ok &= CleanSoinfoList();
    ok &= RenameVmas();
    ok &= CleanLdPreload();
    // UnmapCleanedLibraries 最后执行（最危险）
    ok &= UnmapCleanedLibraries();

    LOG_I("LinkerCleaner: done, cleaned %d libraries", g_cleaned_count);
    return g_cleaned_count > 0;
}

int LinkerCleaner::GetCleanedCount() {
    return g_cleaned_count;
}

// ═══════════════════════════════════════════════════════════
// soinfo 链表清洗
// ═══════════════════════════════════════════════════════════

bool LinkerCleaner::CleanSoinfoList() {
    int api = PathFilter::GetApiLevel();
    auto layout = GetLayout(api);

    // 方法：通过 dl_iterate_phdr 枚举所有已加载库
    // dl_iterate_phdr 内部遍历的就是 soinfo 链表
    // 我们利用回调中的 dl_phdr_info 地址反推 soinfo 地址

    struct EnumContext {
        std::vector<void*> hidden_soinfos;
        std::vector<std::string> hidden_names;
    };

    EnumContext ctx;

    dl_iterate_phdr([](struct dl_phdr_info* info, size_t, void* data) -> int {
        auto* ctx = (EnumContext*)data;
        const char* name = info->dlpi_name;

        if (IsHiddenLib(name)) {
            // dl_phdr_info 在 bionic 中是 soinfo 的一个成员
            // 其偏移在不同版本中不同，但通常是 soinfo 结构体的起始附近
            // 保守做法：记录 dl_phdr_info 地址，后续通过偏移计算 soinfo 地址
            ctx->hidden_soinfos.push_back((void*)info);
            ctx->hidden_names.push_back(name ? name : "(null)");
        }
        return 0;  // 继续枚举
    }, &ctx);

    if (ctx.hidden_soinfos.empty()) {
        LOG_D("LinkerCleaner: no hidden libraries found in soinfo list");
        return true;  // 无需清洗
    }

    LOG_I("LinkerCleaner: found %zu hidden libraries in linker",
          ctx.hidden_soinfos.size());

    // 对每个隐藏的 soinfo，从双向链表中摘除
    // 注意：直接操作 soinfo 内部指针有风险
    // 更安全的做法：修改 dl_iterate_phdr 的遍历行为
    // 但 Momo 不用 dl_iterate_phdr，它直接解析 solist 全局变量

    // 找到 linker 基地址和 solist
    void* linker_base = FindLinkerBase();
    if (!linker_base) {
        LOG_E("LinkerCleaner: cannot find linker base");
        return false;
    }

    void* solist_ptr = FindSolistAddress(linker_base, api);
    if (!solist_ptr) {
        LOG_E("LinkerCleaner: cannot find solist address");
        return false;
    }

    // solist 是一个 soinfo* 全局变量
    // 读取链表头
    void** solist = (void**)solist_ptr;
    void* head = *solist;

    if (!head) {
        LOG_W("LinkerCleaner: solist is null");
        return false;
    }

    // 遍历链表，摘除匹配的节点
    void* prev = nullptr;
    void* current = head;
    int removed = 0;

    while (current) {
        // 读取 soinfo 的名称
        // realpath 字段：Android 12+ 是 std::string，之前是 char[]
        const char* name = nullptr;

        if (layout.realpath_is_std_string) {
            // std::string 布局：{char* data; size_t size; size_t capacity;}
            // 小字符串优化(SSO)时 data 指向自身内部
            char* str_data = *(char**)((char*)current + layout.offset_realpath);
            name = str_data;
        } else {
            name = *(const char**)((char*)current + layout.offset_realpath);
        }

        bool should_remove = IsHiddenLib(name);

        if (should_remove) {
            LOG_I("LinkerCleaner: removing soinfo '%s' from list",
                  name ? name : "(unknown)");

            // 读取 next 指针
            void* next = *(void**)((char*)current + layout.offset_next);

            // 双向链表摘除
            if (prev) {
                *(void**)((char*)prev + layout.offset_next) = next;
            } else {
                // 摘除的是头节点
                *solist = next;
            }
            if (next) {
                *(void**)((char*)next + layout.offset_prev) = prev;
            }

            removed++;
            current = next;
        } else {
            prev = current;
            current = *(void**)((char*)current + layout.offset_next);
        }
    }

    g_cleaned_count += removed;
    LOG_I("LinkerCleaner: removed %d soinfo nodes", removed);
    return true;
}

// ═══════════════════════════════════════════════════════════
// VMA 重命名
// ═══════════════════════════════════════════════════════════

bool LinkerCleaner::RenameVmas() {
    // 读取 /proc/self/maps，找到匹配的行
    // 对匿名映射使用 prctl(PR_SET_VMA_ANON_NAME) 重命名
    // 对文件映射：无法直接重命名，但可以 mremap 后重命名

    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return false;

    // 读取整个 maps（通常 < 256KB）
    char buf[262144];
    long total = 0;
    long n;
    while ((n = read(fd, buf + total, sizeof(buf) - total - 1)) > 0) {
        total += n;
        if (total >= (long)sizeof(buf) - 1) break;
    }
    close(fd);
    buf[total] = '\0';

    int renamed = 0;
    char* line = buf;

    while (line && *line) {
        char* next_line = strchr(line, '\n');
        if (next_line) *next_line = '\0';

        // 检查是否匹配隐藏模式
        bool match = false;
        for (const char* pat : kHiddenPatterns) {
            if (strstr(line, pat)) { match = true; break; }
        }

        if (match) {
            // 解析地址范围
            uintptr_t start, end;
            char perms[5];
            if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
                // 尝试重命名（仅对匿名映射有效）
                // 对文件映射，prctl 会返回 EINVAL，忽略即可
                long ret = prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME,
                                 start, end - start, "[anon:libc_malloc]");
                if (ret == 0) {
                    renamed++;
                }
                // 文件映射无法重命名，由 UnmapCleanedLibraries 处理
            }
        }

        line = next_line ? next_line + 1 : nullptr;
    }

    LOG_I("LinkerCleaner: renamed %d VMAs", renamed);
    return true;
}

// ═══════════════════════════════════════════════════════════
// 卸载已清洗库的文件映射
// ═══════════════════════════════════════════════════════════

bool LinkerCleaner::UnmapCleanedLibraries() {
    // 危险操作：munmap 正在使用的代码段会导致 crash
    // 只 unmap 数据段（rw-p）和只读段（r--p），保留代码段（r-xp）
    // 代码段由 VMA 重命名处理

    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return false;

    char buf[262144];
    long total = 0;
    long n;
    while ((n = read(fd, buf + total, sizeof(buf) - total - 1)) > 0) {
        total += n;
        if (total >= (long)sizeof(buf) - 1) break;
    }
    close(fd);
    buf[total] = '\0';

    // 获取当前 PC，避免 unmap 自己正在执行的代码
    uintptr_t current_pc;
#if defined(__aarch64__)
    asm volatile("adr %0, ." : "=r"(current_pc));
#elif defined(__arm__)
    asm volatile("mov %0, pc" : "=r"(current_pc));
#endif

    int unmapped = 0;
    char* line = buf;

    while (line && *line) {
        char* next_line = strchr(line, '\n');
        if (next_line) *next_line = '\0';

        bool match = false;
        for (const char* pat : kHiddenPatterns) {
            if (strstr(line, pat)) { match = true; break; }
        }

        if (match) {
            uintptr_t start, end;
            char perms[5];
            if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
                // 跳过包含当前 PC 的区域
                if (current_pc >= start && current_pc < end) {
                    line = next_line ? next_line + 1 : nullptr;
                    continue;
                }

                // 只 unmap 非执行段
                if (perms[2] != 'x') {
                    if (munmap((void*)start, end - start) == 0) {
                        unmapped++;
                    }
                }
            }
        }

        line = next_line ? next_line + 1 : nullptr;
    }

    LOG_I("LinkerCleaner: unmapped %d regions", unmapped);
    return true;
}

// ═══════════════════════════════════════════════════════════
// LD_PRELOAD 清洗
// ═══════════════════════════════════════════════════════════

bool LinkerCleaner::CleanLdPreload() {
    // 清除环境变量
    unsetenv("LD_PRELOAD");
    unsetenv("LD_LIBRARY_PATH");

    // 清除 linker 内部的 g_ld_preloads
    // 这需要找到 linker 的全局变量
    // 保守做法：通过 dl_iterate_phdr 检查是否还有 preload 库

    // 同时清除 /proc/self/environ 中的痕迹
    // 这由 seccomp 的 read 过滤处理（FdTracker 会标记 environ）

    LOG_D("LinkerCleaner: LD_PRELOAD cleaned");
    return true;
}

// ═══════════════════════════════════════════════════════════
// 内部辅助
// ═══════════════════════════════════════════════════════════

LinkerCleaner::SoinfoLayout LinkerCleaner::GetLayout(int api_level) {
    // 这些偏移通过逆向 /system/bin/linker64 获得
    // 不同版本差异较大，需要持续维护
    //
    // 参考来源：
    // - AOSP bionic/linker/linker.cpp
    // - 各版本 /system/bin/linker64 的 IDA 分析
    //
    // 注意：这些是推理值，实际部署前必须在目标设备上验证

    SoinfoLayout layout{};

    if (api_level >= 35) {
        // Android 15
        layout = {
            .offset_next = 0x00,
            .offset_prev = 0x08,
            .offset_realpath = 0x1A8,
            .offset_soname = 0x1C8,
            .offset_base = 0x118,
            .offset_size = 0x120,
            .offset_flags = 0x130,
            .realpath_is_std_string = true,
        };
    } else if (api_level >= 34) {
        // Android 14
        layout = {
            .offset_next = 0x00,
            .offset_prev = 0x08,
            .offset_realpath = 0x1A0,
            .offset_soname = 0x1C0,
            .offset_base = 0x110,
            .offset_size = 0x118,
            .offset_flags = 0x128,
            .realpath_is_std_string = true,
        };
    } else if (api_level >= 33) {
        // Android 13
        layout = {
            .offset_next = 0x00,
            .offset_prev = 0x08,
            .offset_realpath = 0x198,
            .offset_soname = 0x1B8,
            .offset_base = 0x108,
            .offset_size = 0x110,
            .offset_flags = 0x120,
            .realpath_is_std_string = true,
        };
    } else if (api_level >= 31) {
        // Android 12/12L
        layout = {
            .offset_next = 0x00,
            .offset_prev = 0x08,
            .offset_realpath = 0x190,
            .offset_soname = 0x1B0,
            .offset_base = 0x100,
            .offset_size = 0x108,
            .offset_flags = 0x118,
            .realpath_is_std_string = true,
        };
    } else {
        // Android 10/11
        layout = {
            .offset_next = 0x00,
            .offset_prev = 0x08,
            .offset_realpath = 0x178,
            .offset_soname = 0x198,
            .offset_base = 0x0E8,
            .offset_size = 0x0F0,
            .offset_flags = 0x100,
            .realpath_is_std_string = false,  // char* 而非 std::string
        };
    }

    return layout;
}

void* LinkerCleaner::FindLinkerBase() {
    void* base = nullptr;

    dl_iterate_phdr([](struct dl_phdr_info* info, size_t, void* data) -> int {
        const char* name = info->dlpi_name;
        if (name && (strstr(name, "/linker64") || strstr(name, "/linker"))) {
            *(void**)data = (void*)info->dlpi_addr;
            return 1;  // 停止
        }
        return 0;
    }, &base);

    return base;
}

void* LinkerCleaner::FindSolistAddress(void* linker_base, int api_level) {
    // solist 是 linker 的 .bss 段中的静态全局变量
    // 定位方法：
    //
    // 方法 1：通过符号（Android 13 及以下可能导出）
    void* handle = dlopen("ld-android.so", RTLD_NOLOAD);
    if (!handle) handle = dlopen(nullptr, RTLD_NOLOAD);

    // 尝试 dlsym 查找（某些版本可用）
    // 注意：Android 14+ 的 linker 不再导出这些符号
    void* sym = dlsym(RTLD_DEFAULT, "__dl__ZL6solist");
    if (sym) return sym;

    sym = dlsym(RTLD_DEFAULT, "solist");
    if (sym) return sym;

    // 方法 2：通过 /proc/self/maps 找到 linker 的 .bss 段
    // 然后在 .bss 中扫描指向第一个 soinfo 的指针
    // 这需要知道第一个 soinfo（通常是 linker 自身）的地址

    // 方法 3：通过 dl_iterate_phdr 的回调地址反推
    // dl_iterate_phdr 内部代码引用了 solist
    // 我们可以 hook dl_iterate_phdr 的 GOT 来获取

    // 方法 4（最可靠）：硬编码偏移
    // 通过逆向特定版本的 linker64 获得 solist 相对于基地址的偏移
    // 这需要为每个 OEM/版本维护一个偏移表

    // 此处使用启发式方法：
    // 扫描 linker 的 .data/.bss 段，找到指向已知 soinfo 的指针
    // 已知 soinfo：dl_iterate_phdr 回调中第一个 dl_phdr_info 的地址

    LOG_W("LinkerCleaner: using heuristic solist search (api=%d)", api_level);

    // 读取 linker 的 maps 条目，找到 rw- 段
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return nullptr;

    char buf[65536];
    long total = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (total <= 0) return nullptr;
    buf[total] = '\0';

    uintptr_t linker_start = (uintptr_t)linker_base;
    uintptr_t bss_start = 0, bss_end = 0;

    char* line = buf;
    while (line && *line) {
        char* next = strchr(line, '\n');
        if (next) *next = '\0';

        if (strstr(line, "linker")) {
            uintptr_t start, end;
            char perms[5];
            if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
                if (perms[0] == 'r' && perms[1] == 'w') {
                    // 找到 rw 段（包含 .data 和 .bss）
                    if (start >= linker_start) {
                        bss_start = start;
                        bss_end = end;
                        break;
                    }
                }
            }
        }
        line = next ? next + 1 : nullptr;
    }

    if (!bss_start || !bss_end) {
        LOG_E("LinkerCleaner: cannot find linker rw segment");
        return nullptr;
    }

    // 在 rw 段中扫描：找到一个指针，其值指向 dl_iterate_phdr
    // 枚举的第一个结果（即 linker 自身的 soinfo）
    // 这个指针就是 solist 的值

    // 获取第一个 soinfo 的地址（linker 自身）
    void* first_soinfo = nullptr;
    dl_iterate_phdr([](struct dl_phdr_info* info, size_t, void* data) -> int {
        // 第一个回调就是主程序或 linker
        *(void**)data = (void*)info;
        return 1;
    }, &first_soinfo);

    if (!first_soinfo) return nullptr;

    // 在 bss 段中搜索指向 first_soinfo 的指针
    uintptr_t* scan = (uintptr_t*)bss_start;
    uintptr_t* scan_end = (uintptr_t*)bss_end;
    uintptr_t target = (uintptr_t)first_soinfo;

    for (; scan < scan_end; scan++) {
        if (*scan == target) {
            LOG_I("LinkerCleaner: found solist at %p (value=%p)",
                  (void*)scan, (void*)*scan);
            return (void*)scan;
        }
    }

    LOG_E("LinkerCleaner: solist not found in linker rw segment");
    return nullptr;
}

} // namespace har
