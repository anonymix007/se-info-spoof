/* Copyright 2022-2023 John "topjohnwu" Wu
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

// This is an attempt to use the public API for Zygisk modules from C (and any language that supports C FFI).

#pragma once

#include <jni.h>

#define ZYGISK_API_VERSION 4

#ifdef __cplusplus
extern "C" {
#endif

typedef struct AppSpecializeArgs {
    // Required arguments. These arguments are guaranteed to exist on all Android versions.
    jint *uid;
    jint *gid;
    jintArray *gids;
    jint *runtime_flags;
    jobjectArray *rlimits;
    jint *mount_external;
    jstring *se_info;
    jstring *nice_name;
    jstring *instruction_set;
    jstring *app_data_dir;

    // Optional arguments. Please check whether the pointer is null before de-referencing
    jintArray *const fds_to_ignore;
    jboolean *const is_child_zygote;
    jboolean *const is_top_app;
    jobjectArray *const pkg_data_info_list;
    jobjectArray *const whitelisted_data_info_list;
    jboolean *const mount_data_dirs;
    jboolean *const mount_storage_dirs;
} AppSpecializeArgs;

typedef struct ServerSpecializeArgs {
    jint *uid;
    jint *gid;
    jintArray *gids;
    jint *runtime_flags;
    jlong *permitted_capabilities;
    jlong *effective_capabilities;
} ServerSpecializeArgs;

// These values are used in Api_setOption(Option)
typedef enum Option {
    // Force Magisk's denylist unmount routines to run on this process.
    //
    // Setting this option only makes sense in preAppSpecialize.
    // The actual unmounting happens during app process specialization.
    //
    // Set this option to force all Magisk and modules' files to be unmounted from the
    // mount namespace of the process, regardless of the denylist enforcement status.
    FORCE_DENYLIST_UNMOUNT = 0,

    // When this option is set, your module's library will be dlclose-ed after post[XXX]Specialize.
    // Be aware that after dlclose-ing your module, all of your code will be unmapped from memory.
    // YOU MUST NOT ENABLE THIS OPTION AFTER HOOKING ANY FUNCTIONS IN THE PROCESS.
    DLCLOSE_MODULE_LIBRARY = 1,
} Option;

// Bit masks of the return value of Api::getFlags()
typedef enum StateFlag {
    // The user has granted root access to the current process
    PROCESS_GRANTED_ROOT = (1u << 0),

    // The current process was added on the denylist
    PROCESS_ON_DENYLIST = (1u << 1),
} StateFlag;

// Register a global structure instance as a Zygisk module

#define REGISTER_ZYGISK_MODULE(abi) \
void zygisk_module_entry(api_table *table, JNIEnv *env) { \
    entry_impl(table, env, &abi);                         \
}

#define REGISTER_ZYGISK_COMPANION(func) \
void zygisk_companion_entry(int client) { func(client); }

typedef struct module_abi module_abi;
typedef struct api_table api_table;

struct module_abi {
    long api_version;
    void *impl;

    void (*preAppSpecialize)(void *, AppSpecializeArgs *);
    void (*postAppSpecialize)(void *, const AppSpecializeArgs *);
    void (*preServerSpecialize)(void *, ServerSpecializeArgs *);
    void (*postServerSpecialize)(void *, const ServerSpecializeArgs *);
};

struct api_table {
    // Base
    void *impl;
    bool (*registerModule)(api_table *, module_abi *);

    void (*hookJniNativeMethods)(JNIEnv *, const char *, JNINativeMethod *, int);
    void (*pltHookRegister)(dev_t, ino_t, const char *, void *, void **);
    bool (*exemptFd)(int);
    bool (*pltHookCommit)();
    int  (*connectCompanion)(void * /* impl */);
    void (*setOption)(void * /* impl */, Option);
    int  (*getModuleDir)(void * /* impl */);
    uint32_t (*getFlags)(void * /* impl */);
};

static inline int Api_connectCompanion(api_table *tbl) {
    return tbl->connectCompanion ? tbl->connectCompanion(tbl->impl) : -1;
}
static inline int Api_getModuleDir(api_table *tbl) {
    return tbl->getModuleDir ? tbl->getModuleDir(tbl->impl) : -1;
}
static inline void Api_setOption(api_table *tbl, Option opt) {
    if (tbl->setOption) tbl->setOption(tbl->impl, opt);
}
static inline uint32_t Api_getFlags(api_table *tbl) {
    return tbl->getFlags ? tbl->getFlags(tbl->impl) : 0;
}
static inline bool Api_exemptFd(api_table *tbl, int fd) {
    return tbl->exemptFd != NULL && tbl->exemptFd(fd);
}
static inline void Api_hookJniNativeMethods(api_table *tbl, JNIEnv *env, const char *className, JNINativeMethod *methods, int numMethods) {
    if (tbl->hookJniNativeMethods) tbl->hookJniNativeMethods(env, className, methods, numMethods);
}
static inline void Api_pltHookRegister(api_table *tbl, dev_t dev, ino_t inode, const char *symbol, void *newFunc, void **oldFunc) {
    if (tbl->pltHookRegister) tbl->pltHookRegister(dev, inode, symbol, newFunc, oldFunc);
}
static inline bool Api_pltHookCommit(api_table *tbl) {
    return tbl->pltHookCommit != NULL && tbl->pltHookCommit();
}

void module_onLoad(void *impl, api_table *api, JNIEnv *env);

static inline void entry_impl(api_table *table, JNIEnv *env, struct module_abi *abi) {
    if (!table->registerModule(table, abi)) return;
    module_onLoad(abi->impl, table, env);
}

__attribute__((visibility("default"))) __attribute__((unused))
void zygisk_module_entry(struct api_table *, JNIEnv *);

__attribute__((visibility("default"))) __attribute__((unused))
void zygisk_companion_entry(int);

#ifdef __cplusplus
}
#endif
