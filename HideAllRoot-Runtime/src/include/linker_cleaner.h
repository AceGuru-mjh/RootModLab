#pragma once

namespace har {

// ═══════════════════════════════════════════════════════════
// Linker 清洗器：从 bionic linker 的 soinfo 链表中
// 摘除 Zygisk/Magisk 相关库，对抗 Momo 的 linker 遍历检测
// ═══════════════════════════════════════════════════════════

class LinkerCleaner {
public:
    // 执行完整清洗（在 postAppSpecialize 中调用）
    // 返回 true 表示至少摘除了一个 soinfo
    static bool Clean();

    // 仅清洗 soinfo 链表
    static bool CleanSoinfoList();

    // 仅重命名 VMA（/proc/self/maps 中的名称）
    static bool RenameVmas();

    // 卸载已摘除库的文件映射
    static bool UnmapCleanedLibraries();

    // 清除 LD_PRELOAD 相关痕迹
    static bool CleanLdPreload();

    // 获取已清洗的库数量
    static int GetCleanedCount();

private:
    // soinfo 结构体偏移（按 API level）
    struct SoinfoLayout {
        size_t offset_next;
        size_t offset_prev;
        size_t offset_realpath;   // std::string 或 const char*
        size_t offset_soname;
        size_t offset_base;
        size_t offset_size;
        size_t offset_flags;
        bool   realpath_is_std_string;  // Android 12+ 使用 std::string
    };

    static SoinfoLayout GetLayout(int api_level);
    static void* FindLinkerBase();
    static void* FindSolistAddress(void* linker_base, int api_level);
};

} // namespace har
