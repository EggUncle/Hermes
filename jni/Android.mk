LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog
LOCAL_MODULE := binderhook
LOCAL_SRC_FILES := hook_util.c
LOCAL_SRC_FILES += binder_util.c
LOCAL_SRC_FILES += elf_util.c
LOCAL_SRC_FILES += entry.c

LOCAL_C_INCLUDES += $(PROJECT_PATH)../include

include $(BUILD_SHARED_LIBRARY)
