LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog
LOCAL_MODULE := binderhook
LOCAL_SRC_FILES := bind_hook_utils.c \
                    binder_hook.c \
                    elf_util.c

LOCAL_C_INCLUDES += $(PROJECT_PATH)../include

include $(BUILD_SHARED_LIBRARY)
