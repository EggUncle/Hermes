//
// Created by egguncle on 2018/11/26.
//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <elf.h>
#include <unistd.h>
#include <sys/time.h>
#include "include/bind_hook_utils.h"
#include "include/binder_hook.h"
#include "include/elf_util.h"
#include "include/binder.h"

char *hexdump(binder_uintptr_t _data, binder_size_t len, int dump_all) {
    //hex_data_dump(_data, len);

    char *data = (char *) _data;
    char *dataAry = (char *) malloc(len * (sizeof(char)));
    char *dataTmp = dataAry;
    binder_size_t count;
    for (count = 0; count < len; count++) {
        if ((*data >= 33) && (*data <= 122)) {
            *dataAry = *data;
            dataAry++;
        } else if (dump_all == DUMP_ALL) {
            *dataAry = '.';
            dataAry++;
        }
        data++;
    }
    *dataAry = '\0';
    return dataTmp;
}

long get_current_time() {
    struct timeval tv;

    gettimeofday(&tv, NULL);

    return tv.tv_sec * 1000 + tv.tv_usec / 1000;

}

void hex_data_dump(struct binder_transaction_data *transaction_data) {

    binder_uintptr_t _data = transaction_data->data.ptr.buffer;
    binder_size_t len = transaction_data->data_size;
    char *pname = hexdump(_data, len, ONLY_CHAR);
    LOGE("PID = %d,code = %d, dump name : %s , pname size is %ld, data size is %lld\n",
         transaction_data->sender_pid, transaction_data->code, pname, strlen(pname),
         transaction_data->data_size);
    unsigned int *data = (unsigned int *) _data;
    binder_size_t count;
    LOGE("---hex data---\n");
    for (count = 0; count < len / 4; count += 2) {
        char *tmp1 = malloc(sizeof(char) * 8);
        char *tmp2 = malloc(sizeof(char) * 4);
        char *tmp3 = malloc(sizeof(char) * 8);
        char *tmp4 = malloc(sizeof(char) * 4);
        char *tmp5 = malloc(sizeof(char) * 8);
        char *tmp6 = malloc(sizeof(char) * 4);
        char *tmp7 = malloc(sizeof(char) * 8);
        char *tmp8 = malloc(sizeof(char) * 4);

        sprintf(tmp1, "%08X", *data);
        sprintf(tmp2, "%s", hexdump(data, 4, DUMP_ALL));


        if (count < len / 4) {
            data++;
            count++;
            sprintf(tmp3, "%08x", *data);
            sprintf(tmp4, "%s", hexdump(data, 4, DUMP_ALL));
        } else {
            *tmp3 = "    ";
            *tmp4 = "    ";
        }

        if (count < len / 4) {
            data++;
            count++;
            sprintf(tmp5, "%08x", *data);
            sprintf(tmp6, "%s", hexdump(data, 4, DUMP_ALL));
        } else {
            *tmp5 = "    ";
            *tmp6 = "    ";
        }

        if (count < len / 4) {
            data++;
            count++;
            sprintf(tmp7, "%08x", *data);
            sprintf(tmp8, "%s", hexdump(data, 4, DUMP_ALL));

        } else {
            *tmp7 = "    ";
            *tmp8 = "    ";
        }
        LOGE("%.8s %.8s %.8s %.8s  %s%s%s%s", tmp1, tmp3, tmp5, tmp7, tmp2, tmp4, tmp6, tmp8);
        data++;

        free(tmp1);
        free(tmp2);
        free(tmp3);
        free(tmp4);
        free(tmp5);
        free(tmp6);
        free(tmp7);
        free(tmp8);
    }



//    char *file_name = malloc(sizeof(char) * 32);
//    sprintf(file_name, "/sdcard/tmp/%ld.hex", get_current_time());
//    LOGE("---hex data dump---%s\n", file_name);
//    FILE *file = fopen(file_name, "wab");
//    //LOGE("---hex data dump2---\n");
//    fwrite(_data, len, 1, file);
//    fclose(file);
//    free(file_name);
//    LOGE("---hex data dump---\n");
}

void *get_libs_addr(pid_t pid, char *lib_name) {
    char mapsPath[32];
    long addr = 0;
    if (pid < 0) {
        sprintf(mapsPath, "/proc/self/maps");
    } else {
        sprintf(mapsPath, "/proc/%d/maps", pid);
    }
    FILE *maps = fopen(mapsPath, "r");
    char str_line[1024];
    //  printf("%s", mapsPath);
    while (!feof(maps)) {
        fgets(str_line, 1024, maps);
        if (strstr(str_line, lib_name) != NULL) {
            fclose(maps);
            addr = strtoul(strtok(str_line, "-"), NULL, 16);
            //LOGI("%lx\n", addr);
            if (addr == 0x8000)
                addr = 0;
            break;
        }

    }
    fclose(maps);
    return (void *) addr;
}

void *get_segment_base_address(int fd, void *base_addr, int phnum, size_t phsize,
                               unsigned long phdr_addr) {
    if (phnum > 0) {
        Elf_Phdr phdr;
        lseek(fd, phdr_addr, SEEK_SET);//将指针移至程序头表偏移地址
        for (Elf_Half i = 0; i < phnum; i++) {
            read(fd, &phdr, phsize);
            if (phdr.p_type == PT_LOAD)
                break;

        }
        return base_addr + phdr.p_offset - phdr.p_vaddr;
    }
    return 0;
}
