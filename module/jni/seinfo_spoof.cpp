#include <string>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <android/log.h>

#include "zygisk.hpp"

using std::string;

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "SeInfoSpoofer", __VA_ARGS__)

class SeInfoSpoofModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        const char *process_chars = env->GetStringUTFChars(args->nice_name, nullptr);
        string process(process_chars);
        env->ReleaseStringUTFChars(args->nice_name, process_chars);
        
        const char *se_info_chars = env->GetStringUTFChars(args->se_info, nullptr);
        string se_info(se_info_chars);
        env->ReleaseStringUTFChars(args->nice_name, se_info_chars);
        
        preSpecialize(args, process, se_info);
    }

    void preServerSpecialize(ServerSpecializeArgs *args) override {
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

private:
    Api *api;
    JNIEnv *env;

    void preSpecialize(AppSpecializeArgs *args, const string &process, const string &se_info) {
        if (process.rfind("com.android.bluetooth", 0) != 0) {
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }
        LOGD("process=[%s], se_info=[%s] changed to [platform:privapp:targetSdkVersion=33:complete]\n", process.c_str(), se_info.c_str());
        args->se_info = env->NewStringUTF("platform:privapp:targetSdkVersion=33:complete");
    }

};

REGISTER_ZYGISK_MODULE(SeInfoSpoofModule)
