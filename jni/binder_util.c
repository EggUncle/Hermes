//
// Created by egguncle on 2019/4/12.
//


#include <malloc.h>
#include "include/binder.h"
#include "include/binder_util.h"
#include <time.h>
#include "include/log.h"
#include <string.h>

#define DUMP_ALL 1
#define ONLY_CHAR 0
#define PLACE_HOLDER "        "

struct hex_data {
    char *hex;
    char *str;
};

void hex_data_init(struct hex_data *data, int length) {
    data->hex = calloc(1, 2 * length * sizeof(char) + 1);
    data->str = calloc(1, length * sizeof(char) + 1);
}

void hex_data_clean(struct hex_data *data) {
    free(data->hex);
    free(data->str);
}

int hexdump(binder_uintptr_t binder_data, binder_size_t len, struct hex_data *h_data,
            int dump_all) {
    char *data = (char *) binder_data;
    char tmp_str[1];
    char tmp_hex[2];
    int index = 0;
    for (int count = 0; count < len; count++) {
        int ascii = *data;
        sprintf(tmp_hex, "%02x", ascii);
        memcpy(h_data->hex + count * 2, tmp_hex, 2);
        if ((*data >= 33) && (*data <= 122)) {
            sprintf(tmp_str, "%c", *data);
            memcpy(h_data->str + index, tmp_str, 1);
            index++;
        } else if (dump_all == DUMP_ALL) {
            memcpy(h_data->str + index, ".", 1);
            index++;
        }
        data++;
    }
    memcpy(h_data->hex + len * 2 + 1, "\0", 1);
    memcpy(h_data->str + index + 1, "\0", 1);
}

int parse_binder_data(struct binder_transaction_data *transaction_data) {
    binder_uintptr_t _data = transaction_data->data.ptr.buffer;
    binder_size_t len = transaction_data->data_size;
    struct hex_data h_data[1];
    hex_data_init(h_data, len);
    hexdump(_data, len, h_data, ONLY_CHAR);
    LOGE("PID = %d, code = %d, dump name : %s , pname size is %d, data size is %lld , target is %llx  %llx offset is %lx\n",
         transaction_data->sender_pid, transaction_data->code, h_data->str, strlen(h_data->str),
         transaction_data->data_size, &transaction_data->target.handle,
         &transaction_data->target.ptr, transaction_data->data.ptr.offsets);
    hex_data_clean(h_data);
    hex_data_init(h_data, len);
    hexdump(_data, len, h_data, DUMP_ALL);
    int i = 0;
    char *tmp_str = calloc(1, sizeof(char) * 16 + 1);
    char *tmp_hex = calloc(1, sizeof(char) * 8 + 1);
    char *tmp_hex_2 = calloc(1, sizeof(char) * 8 + 1);
    char *tmp_hex_3 = calloc(1, sizeof(char) * 8 + 1);
    char *tmp_hex_4 = calloc(1, sizeof(char) * 8 + 1);
    int str_start_index = 0;
    do {
        str_start_index = 4;
        memcpy(tmp_hex, h_data->hex + i * 2, 8);
        memcpy(tmp_hex + 8, "\0", 1);
        if (i * 2 + 16 <= len * 2) {
            str_start_index = 8;
            memcpy(tmp_hex_2, h_data->hex + i * 2 + 8, 8);
            memcpy(tmp_hex_2 + 8, "\0", 1);
        } else {
            memcpy(tmp_hex_2, PLACE_HOLDER, 8);
            memcpy(tmp_hex_2 + 8, "\0", 1);
        }
        if (i * 2 + 24 <= len * 2) {
            str_start_index = 12;
            memcpy(tmp_hex_3, h_data->hex + i * 2 + 16, 8);
            memcpy(tmp_hex_3 + 8, "\0", 1);
        } else {
            memcpy(tmp_hex_3, PLACE_HOLDER, 8);
            memcpy(tmp_hex_3 + 8, "\0", 1);
        }
        if (i * 2 + 32 <= len * 2) {
            str_start_index = 16;
            memcpy(tmp_hex_4, h_data->hex + i * 2 + 24, 8);
            memcpy(tmp_hex_4 + 8, "\0", 1);
        } else {
            memcpy(tmp_hex_4, PLACE_HOLDER, 8);
            memcpy(tmp_hex_4 + 8, "\0", 1);
        }
        memcpy(tmp_str, h_data->str + i, str_start_index);
        memcpy(tmp_str + str_start_index, "\0", 1);
        LOGD("%s %8s %8s %8s  %s", tmp_hex, tmp_hex_2, tmp_hex_3, tmp_hex_4, tmp_str);
        i += 16;
    } while (i < len);
    free(tmp_hex);
    free(tmp_hex_2);
    free(tmp_hex_3);
    free(tmp_hex_4);
    free(tmp_str);
    return 0;
}