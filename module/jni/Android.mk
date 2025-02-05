LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := seinfo_spoof
LOCAL_SRC_FILES := seinfo_spoof.c apk_sign.c alg-sha256.c
LOCAL_LDLIBS := -llog
LOCAL_CFLAGS := -fvisibility=hidden -std=gnu2x
include $(BUILD_SHARED_LIBRARY)
