LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := kallsyms.c exp_sys_call.c getroot.c 

LOCAL_CFLAGS := -marm -O0

LOCAL_C_INCLUDES := $(LOCAL_PATH)/../include/ $(LOCAL_PATH)/../ $(LOCAL_PATH)/../utils/

LOCAL_MODULE := libcommon
LOCAL_MODULE_TAGS := optional

include $(BUILD_STATIC_LIBRARY)
