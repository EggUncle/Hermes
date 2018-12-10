//
// Created by egguncle on 2018/11/26.
//

#include <sys/types.h>

#include <android/log.h>
#include "binder.h"

#define TAG "LIB_BINDER_HOOK" // 这个是自定义的LOG的标识
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,TAG ,__VA_ARGS__) // 定义LOGD类型
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,TAG ,__VA_ARGS__) // 定义LOGI类型
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,TAG ,__VA_ARGS__) // 定义LOGW类型
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,TAG ,__VA_ARGS__) // 定义LOGE类型
#define LOGF(...) __android_log_print(ANDROID_LOG_FATAL,TAG ,__VA_ARGS__) // 定义LOGF类型

#define DUMP_ALL 1
#define ONLY_CHAR 0


void *get_libs_addr(pid_t pid, char *lib_name);

void *get_segment_base_address(int fd, void *base_addr, int phnum, size_t phsize,
                               unsigned long phdr_addr);

char *hexdump(binder_uintptr_t _data, binder_size_t len, int dump_all);

void hex_data_dump(struct binder_transaction_data *transaction_data);

long get_current_time();
