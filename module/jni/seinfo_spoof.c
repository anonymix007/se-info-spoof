#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <android/log.h>

#include "zygisk.h"

#include "apk_sign.h"

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "SeInfoSpoofer", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "SeInfoSpoofer", __VA_ARGS__)

typedef struct {
    api_table *api;
    JNIEnv *env;
} se_info_spoof_module_t;

void module_onLoad(void *impl, struct api_table *api, JNIEnv *env) {
    se_info_spoof_module_t *module = impl;

    module->api = api;
    module->env = env;
}

#define STARTSWITH(str, pre) (strncmp(pre, str, strlen(pre)) == 0)

#define PLATFORM_SEINFO "platform:privapp:targetSdkVersion=34:complete"
#define PROCESS_NAME    "com.android.bluetooth"

static bool write_int(int fd, int val) {
    if (write(fd, &val, sizeof(val)) != sizeof(val)) {
        LOGE("Failed to write %d to companion: %s", val, strerror(errno));
        return false;
    }
    return true;
}

static bool write_string(int fd, const char *val) {
    size_t len = strlen(val);
    if (!write_int(fd, len)) return false;
    if (write(fd, val, len) != len) {
        LOGE("Failed to write %s to companion: %s", val, strerror(errno));
        return false;
    }
    return true;
}

static bool read_int(int fd, int *val) {
    if (read(fd, val, sizeof(*val)) != sizeof(*val)) {
        LOGE("Failed to read int from companion: %s", strerror(errno));
        return false;
    }
    return true;
}

static bool read_string(int fd, int *len, char **val) {
    if (!read_int(fd, len)) return false;
    *val = malloc(*len);
    if (read(fd, *val, *len) != *len) {
        LOGE("Failed to read string from companion: %s", strerror(errno));
        return false;
    }
    return true;
}

static void preSpecialize(api_table *api, JNIEnv *env, AppSpecializeArgs *args, const char *process, const char *se_info) {
    if (!STARTSWITH(process, PROCESS_NAME)) {
        Api_setOption(api, DLCLOSE_MODULE_LIBRARY);
        return;
    }
    LOGD("process=[%s], se_info=[%s], gid=[%d], uid=[%d]", process, se_info, *args->gid, *args->uid);

    int fd = Api_connectCompanion(api);
    if (fd < 0) {
        LOGE("Failed to connect to companion: %s", strerror(errno));
        return;
    }

    if (!write_int(fd, 1)) return;
    if (!write_int(fd, *args->uid)) return;
    if (!write_string(fd, process)) return;

    int status = false;
    if (!read_int(fd, &status)) return;

    LOGD("process=[%s], apk signature verification %s", process, status ? "passed!" : "failed");

    if (!status) {
        LOGE("APK signature check failed");
        return;
    }

    // TODO: is `(*env)->DeleteLocalRef(env, *args->se_info);` needed here?
    *args->se_info = (*env)->NewStringUTF(env, PLATFORM_SEINFO);
    LOGD("process=[%s], se_info changed to ["PLATFORM_SEINFO"]", process);
}

void module_preAppSpecialize(void *impl, AppSpecializeArgs *args) {
    se_info_spoof_module_t *module = impl;

    const char *process_chars = (*module->env)->GetStringUTFChars(module->env, *args->nice_name, NULL);
    const char *se_info_chars = (*module->env)->GetStringUTFChars(module->env, *args->se_info, NULL);

    preSpecialize(module->api, module->env, args, process_chars, se_info_chars);

    (*module->env)->ReleaseStringUTFChars(module->env, &args->nice_name, process_chars);
    (*module->env)->ReleaseStringUTFChars(module->env, &args->nice_name, se_info_chars);
}

void module_postAppSpecialize(void *impl, const AppSpecializeArgs *args) {
    se_info_spoof_module_t *module = impl;
    Api_setOption(module->api, DLCLOSE_MODULE_LIBRARY);
}

void module_preServerSpecialize(void *impl, ServerSpecializeArgs *args) {
    /* Do nothing */
}

void module_postServerSpecialize(void *impl, const ServerSpecializeArgs *args) {
    /* Do nothing */
}

#define CERT_SHA256_FINGERPRINT "bd94126d9ac1a4e5f1017b70f0414c040ab7800c781e60ae452a33c71080cde6"

void se_info_companion(int fd) {
    int cmd, uid, len;
    char *process = NULL;
    if (!read_int(fd, &cmd)) return;
    if (cmd != 1) {
        LOGE("Wrong command: %d", cmd);
    }
    if (!read_int(fd, &uid)) return;
    LOGD("UID: %d", uid);

    if (!read_string(fd, &len, &process)) return;
    LOGD("Process: %s", process);

    char buf[PATH_MAX] = {};
    snprintf(buf, PATH_MAX, "cmd package list packages -f %s", process);

    FILE *out = popen(buf, "r");

    bool success = false;

    while (fgets(buf, PATH_MAX, out)) {
        size_t len = strnlen(buf, PATH_MAX);
        if (buf[len - 1] == '\n') {
            buf[--len] = '\0';
        }

        char *delim = strrchr(buf, '=');

        if (delim == NULL) {
            LOGE("Failed to parse package manager output: \"%s\"", buf);
            continue;
        }
        *delim = '\0';
        const char *apk = buf + strlen("package:");
        const char *package = delim + 1;

        if (strcmp(package, process) == 0) {
            LOGD("APK path: \"%s\"", apk);
            if (check_apk_signature(apk, CERT_SHA256_FINGERPRINT)) {
                success = true;
                break;
            }
        } else {
            LOGD("Wrong package: %s != %s", package, process);
        }
    }

    write_int(fd, success);
    free(process);
    pclose(out);
}

se_info_spoof_module_t priv = {};
struct module_abi se_info_spoof_module = {
    .api_version = ZYGISK_API_VERSION,
    .impl = &priv,

    .preAppSpecialize = module_preAppSpecialize,
    .postAppSpecialize = module_postAppSpecialize,
    .preServerSpecialize = module_preServerSpecialize,
    .postServerSpecialize = module_postServerSpecialize,
};

REGISTER_ZYGISK_MODULE(se_info_spoof_module)
REGISTER_ZYGISK_COMPANION(se_info_companion)
