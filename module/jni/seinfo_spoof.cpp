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
        // Use JNI to fetch our process name
        const char *process_chars = env->GetStringUTFChars(args->nice_name, nullptr);
        string process(process_chars);
        env->ReleaseStringUTFChars(args->nice_name, process_chars);
        
        const char *se_info_chars = env->GetStringUTFChars(args->se_info, nullptr);
        string se_info(se_info_chars);
        env->ReleaseStringUTFChars(args->nice_name, se_info_chars);
        
        preSpecialize(process, se_info);
    }

    void preServerSpecialize(ServerSpecializeArgs *args) override {
        preSpecialize("system_server", "none");
    }

private:
    Api *api;
    JNIEnv *env;

    void preSpecialize(const string &process, const string &se_info) {
        if (process.rfind("com.android.bluetooth", 0) != 0) {
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }
        // Demonstrate connecting to to companion process
        // We ask the companion for a random number
        // unsigned r = 0;
        // int fd = api->connectCompanion();
        // read(fd, &r, sizeof(r));
        // close(fd);
        LOGD("process=[%s], se_info=[%s]\n", process.c_str(), se_info.c_str());

        // Since we do not hook any functions, we should let Zygisk dlclose ourselves
    }

};

//static int urandom = -1;

//static void companion_handler(int i) {
//    if (urandom < 0) {
//        urandom = open("/dev/urandom", O_RDONLY);
//    }
//    unsigned r;
//    read(urandom, &r, sizeof(r));
//    LOGD("companion r=[%u]\n", r);
//    write(i, &r, sizeof(r));
//}

// Register our module class and the companion handler function
REGISTER_ZYGISK_MODULE(SeInfoSpoofModule)
//REGISTER_ZYGISK_COMPANION(companion_handler)
