/*
 * Public Zygisk API header for module developers.
 *
 * Reconstructed 1:1 against Magisk's internal
 * `native/src/core/zygisk/{module.hpp,api.hpp}` ABI so it compiles cleanly and
 * links against the loader at runtime.
 *
 * CRITICAL LAYOUT NOTE
 * --------------------
 * At load time the Zygisk loader passes its internal `ApiTable` (a union of
 * api_abi_v1/v2/v4 whose first member is `api_abi_base { ZygiskModule *impl;
 * bool (*registerModule)(...); }`) to the module reinterpreted as `Api *`.
 * Therefore this `Api` class must reproduce the *exact* memory layout of
 * `api_abi_v2` (the version that is present in every loader): `impl`,
 * `registerModule`, then the eight callback pointers, in that order. The
 * inline methods forward `impl` as the first argument to the C-style
 * callbacks, exactly as the loader expects.
 *
 * Only the symbols below are stable across versions; do not rely on anything
 * outside this header.
 */
#pragma once

#include <jni.h>
#include <sys/types.h>

namespace zygisk {

class Api;
class AppSpecializeArgs;
class ServerSpecializeArgs;

/**
 * Base class every Zygisk module must derive from and register with
 * REGISTER_ZYGISK_MODULE.
 */
class Module {
public:
    virtual void onLoad([[maybe_unused]] Api *api, [[maybe_unused]] JNIEnv *env) {}
    virtual void preAppSpecialize([[maybe_unused]] AppSpecializeArgs *args) {}
    virtual void postAppSpecialize([[maybe_unused]] AppSpecializeArgs *args) {}
    virtual void preServerSpecialize([[maybe_unused]] ServerSpecializeArgs *args) {}
    virtual void postServerSpecialize([[maybe_unused]] ServerSpecializeArgs *args) {}

    // Populated by the loader before onLoad() is invoked.
    Api *api{};
};

/**
 * Arguments passed to preAppSpecialize / postAppSpecialize.
 * Layout matches the loader's AppSpecializeArgs_v5 (== v3 base + the trailing
 * mount_sysprop_overrides pointer), so a reinterpret_cast from the loader side
 * is layout-compatible.
 */
class AppSpecializeArgs {
public:
    jint &uid;
    jint &gid;
    jintArray &gids;
    jint &runtime_flags;
    jobjectArray &rlimits;
    jint &mount_external;
    jstring &se_info;
    jstring &nice_name;
    jstring &instruction_set;
    jstring &app_data_dir;

    jintArray *fds_to_ignore;
    jboolean *is_child_zygote;
    jboolean *is_top_app;
    jobjectArray *pkg_data_info_list;
    jobjectArray *whitelisted_data_info_list;
    jboolean *mount_data_dirs;
    jboolean *mount_storage_dirs;
    jboolean *mount_sysprop_overrides;
};

class ServerSpecializeArgs {
public:
    jint &uid;
    jint &gid;
    jintArray &gids;
    jint &runtime_flags;
    jlong &permitted_capabilities;
    jlong &effective_capabilities;
};

/**
 * Options accepted by Api::setOption.
 */
enum Option : int {
    FORCE_DENYLIST_UNMOUNT = 0,
    DLOPEN_DEDUPLICATE    = 1,
    // Unload the module library after specialization. NOTE: enabling this while
    // PLT hooks are still registered would leave dangling function pointers and
    // crash the target process, so HideAllRoot deliberately does NOT use it and
    // instead hides its own .so via /proc/self/maps line filtering.
    DLCLOSE_MODULE_LIBRARY = 2,
};

/**
 * Per-process state flags returned by Api::getFlags().
 */
enum StateFlag : uint32_t {
    PROCESS_GRANTED_ROOT  = 1u << 0,
    PROCESS_ON_DENYLIST   = 1u << 1,
    PROCESS_IS_MAGISK_APP = 1u << 2,
    DENYLIST_ENFORCED     = 1u << 3,
};

/**
 * The API surface exposed to modules — mirrors api_abi_v2 layout exactly.
 * `impl` and `registerModule_` occupy the first two slots (matching
 * api_abi_base); the remaining slots are the loader callbacks.
 */
class Api {
    void *impl_;                                   // ZygiskModule *
    [[maybe_unused]] bool (*registerModule_)(void *, long *); // internal, unused by modules

    bool (*hookJniNativeMethods_)(JNIEnv *, const char *, JNINativeMethod *, int);
    void (*pltHookRegister_)(const char *, const char *, void *, void **);
    void (*pltHookExclude_)(const char *, const char *);
    bool (*pltHookCommit_)();

    int (*connectCompanion_)(void *);
    void (*setOption_)(void *, Option);
    int (*getModuleDir_)(void *);
    uint32_t (*getFlags_)(void *);

public:
    void setOption(Option opt) { setOption_(impl_, opt); }

    int connectCompanion() { return connectCompanion_(impl_); }

    int getModuleDir() { return getModuleDir_(impl_); }

    uint32_t getFlags() { return getFlags_(impl_); }

    bool hookJniNativeMethods(JNIEnv *env, const char *className,
                              JNINativeMethod *methods, int numMethods) {
        hookJniNativeMethods_(env, className, methods, numMethods);
        return true;
    }

    void pltHookRegister(const char *lib_name, const char *sym_name,
                         void *new_func, void **old_func) {
        pltHookRegister_(lib_name, sym_name, new_func, old_func);
    }

    void pltHookExclude(const char *lib_name, const char *sym_name) {
        pltHookExclude_(lib_name, sym_name);
    }

    bool pltHookCommit() { return pltHookCommit_(); }
};

using zygisk_module_ctor_t = zygisk::Module *(*)();

// Loader entry point implemented by REGISTER_ZYGISK_MODULE.
extern "C" void zygisk_module_entry(zygisk::Api *api, JNIEnv *env,
                                    zygisk::Module *&module);

} // namespace zygisk

/**
 * Register a Zygisk module class. Place this macro exactly once in a
 * translation unit of your module.
 */
#define REGISTER_ZYGISK_MODULE(cls)                                                 \
    extern "C" [[gnu::visibility("default")]] void zygisk_module_entry(             \
            zygisk::Api *api, JNIEnv *env, zygisk::Module *&module) {               \
        module = new cls();                                                          \
        module->api = api;                                                           \
        module->onLoad(api, env);                                                   \
    }
