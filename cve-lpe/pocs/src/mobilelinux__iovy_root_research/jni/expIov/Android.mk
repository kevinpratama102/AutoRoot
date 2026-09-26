LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := iov_exp_main.c flex_array.c

LOCAL_CFLAGS := -marm -O0

LOCAL_C_INCLUDES := $(LOCAL_PATH)/include/ $(LOCAL_PATH)/../ $(LOCAL_PATH)/../common/ $(LOCAL_PATH)/../utils

LOCAL_MODULE := libiovy
LOCAL_MODULE_TAGS := optional

include $(BUILD_STATIC_LIBRARY)
