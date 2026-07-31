LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

# Magisk's Zygisk loader expects the library to be named EXACTLY libzygisk.so
# and placed under <module>/zygisk/<abi>/libzygisk.so
LOCAL_MODULE    := zygisk
LOCAL_SRC_FILES := main.cpp seccomp_poc.cpp
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include

# Self-contained: static STL, only libc/libdl/liblog dependencies.
LOCAL_LDLIBS    := -llog -ldl
LOCAL_CFLAGS    := -std=c++17 -Wall -Wextra -O2 -fvisibility=hidden \
                   -fno-rtti -fno-exceptions -ffunction-sections -fdata-sections
LOCAL_CPPFLAGS  := -std=c++17
LOCAL_ARM_MODE  := arm

include $(BUILD_SHARED_LIBRARY)
