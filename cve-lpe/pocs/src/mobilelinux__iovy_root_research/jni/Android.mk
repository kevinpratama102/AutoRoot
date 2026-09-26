MY_LOCAL_PATH := $(call my-dir)

LOCAL_PATH := $(MY_LOCAL_PATH)

COMMON_LOCAL_PATH := $(MY_LOCAL_PATH)/common
IOV_LOCAL_PATH := $(MY_LOCAL_PATH)/expIov

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= main.cpp                            
                  
LOCAL_MODULE:= root-research

LOCAL_C_INCLUDES := $(LOCAL_PATH)/common $(IOV_LOCAL_PATH)

LOCAL_CFLAGS := -rdynamic -DANDROID -marm -O0 \
    -DHAVE_PTHREADS -DHAVE_SYS_UIO_H -DPERSIST_ASYNC \
      -fno-stack-protector -fpermissive -pie -fPIE

LOCAL_LDFLAGS := -pie -fPIE 

LOCAL_STATIC_LIBRARIES := libiovy libcommon

LOCAL_LDLIBS := -llog  -lz

include $(BUILD_EXECUTABLE)

###########################
# common lib
##########################
include $(COMMON_LOCAL_PATH)/Android.mk

###########################
# expIov lib
##########################
include $(IOV_LOCAL_PATH)/Android.mk

