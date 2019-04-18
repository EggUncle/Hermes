//
// Created by egguncle on 2019/4/12.
//

#include <malloc.h>
#include <memory.h>
#include <sys/user.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include "include/binder.h"
#include "include/binder_util.h"
#include "include/elf_util.h"
#include "include/log.h"

int (*old_ioctl)(int __fd, unsigned long int __request, void *arg);

int new_ioctl(int __fd, unsigned long int __request, void *arg) {
//./data/local/tmp/ptraceMain system_server hook_entry /data/local/tmp/libbinderhook.so
//./data/local/tmp/ptraceMain com.android.phone hook_entry /data/local/tmp/libbinderhook-lib.so
//./data/local/tmp/ptraceMain com.test.gothooktest hook_entry /data/local/tmp/libbinderhook.so
    if (__request == BINDER_WRITE_READ) {
        struct binder_write_read *tmp = (struct binder_write_read *) arg;
        binder_size_t read_size = tmp->read_size;
        binder_size_t write_size = tmp->write_size;
        LOGE("---------------------------------\n");
        if (read_size > 0) {
            binder_size_t already_got_size = tmp->read_consumed;
            void *pret = 0;
            while (already_got_size < read_size) {//循环处理read_buffer中的每一个命令
                pret = (uint32_t *) (tmp->read_buffer + already_got_size);
                uint32_t cmd = *(uint32_t *) pret;//获得命令码
                pret += sizeof(uint32_t);
                binder_size_t size = _IOC_SIZE(cmd);  //从命令参数中解析出用户数据大小
                struct binder_transaction_data *pdata = (struct binder_transaction_data *) pret;

                switch (cmd) {
                    case BR_TRANSACTION: {
                        LOGE("read BR_TRANSACTION");
                        parse_binder_data(pdata);
                    }
                        break;
                    case BR_REPLY: {
                        LOGE("read BR_REPLY");
                        parse_binder_data(pdata);
                    }
                        break;
                    default:
                        break;
                }
                already_got_size += size + 4;//数据内容加上命令码
            }
        }
        if (write_size > 0) {
            binder_size_t already_got_size = tmp->write_consumed;
            void *pret = 0;
            while (already_got_size < read_size) {//循环处理read_buffer中的每一个命令
                pret = (uint32_t *) (tmp->write_buffer + already_got_size);
                uint32_t cmd = *(uint32_t *) pret;//获得命令码
                pret += sizeof(uint32_t);
                binder_size_t size = _IOC_SIZE(cmd);  //从命令参数中解析出用户数据大小
                struct binder_transaction_data *pdata = (struct binder_transaction_data *) pret;

                switch (cmd) {
                    case BC_TRANSACTION: {
                        LOGE("write BC_TRANSACTION");
                        parse_binder_data(pdata);
                    }
                        break;
                    case BC_REPLY: {
                        LOGE("write BC_REPLY");
                        parse_binder_data(pdata);
                    }
                        break;
                    default:
                        break;
                }
                already_got_size += size + 4;//数据内容加上命令码
            }
        }
    }

    return old_ioctl(__fd, __request, arg);
}

int got_hook(char *path, char *target_func_name, int *old_func, void *new_func) {

    FILE *elf_file = open_elf(path);
    if (elf_file == NULL) {
        LOGD("elf file is null \n");
        return 0;
    }
    Elf_Ehdr *elf_header = (Elf_Ehdr *) malloc(sizeof(Elf_Ehdr));
    parse_elf_header(elf_header, elf_file);
    if (elf_header == NULL) {
        LOGD("elf_head  is null \n");
        return 0;
    }

    int fd = open(path, O_RDONLY);
    long target_lib_base_addr = get_libs_addr(-1, path);
    LOGD("target base addr is %lx\n", target_lib_base_addr);
    //基址不一定是maps中的地址，当第一个PT_LOAD 的vaddr不为0的时候，需要进行额外的计算
    unsigned long phdr_addr = elf_header->e_phoff;//程序头表在文件中的偏移量
    int phnum = elf_header->e_phnum;//程序头表表项数目
    size_t phsize = elf_header->e_phentsize;//程序头表项的大小
    long bias = get_segment_base_address(fd, target_lib_base_addr, phnum, phsize,
                                          phdr_addr);//获得该段的内存基址
    LOGD("target segment base address is %lx\n", bias);
    //read shstrtab content
    char *shstrtab_content = parse_shstrtab_content(elf_file, elf_header);
    Elf_Shdr *dynsym_header = parse_target_table_data(shstrtab_content, elf_file, elf_header,
                                                      ".dynsym");
    Elf_Shdr *dynstr_header = parse_target_table_data(shstrtab_content, elf_file, elf_header,
                                                      ".dynstr");
    //read dynstr data
    char *dynstr = (char *) malloc(sizeof(char) * dynstr_header->sh_size);
    fseek(elf_file, dynstr_header->sh_offset, SEEK_SET);
    fread(dynstr, dynstr_header->sh_size, 1, elf_file);

    Elf_Sym *dynsymtab = (Elf_Sym *) malloc(dynsym_header->sh_size);
    fseek(elf_file, dynsym_header->sh_offset, SEEK_SET);
    fread(dynsymtab, dynsym_header->sh_size, 1, elf_file);

    long result_offset = 0;
    //search target in rela.plt
    Elf_Shdr *rela_plt_header = parse_target_table_data(shstrtab_content, elf_file, elf_header,
                                                        ".rela.plt");
    Elf64_Rela *rela_plt_tab = malloc(rela_plt_header->sh_size);

    fseek(elf_file, rela_plt_header->sh_offset, SEEK_SET);
    fread(rela_plt_tab, rela_plt_header->sh_size, 1, elf_file);
    LOGD("rela_plt size %llx\n",
         rela_plt_header->sh_size / rela_plt_header->sh_entsize);
         LOGD("rela_plt en size %ld   sizeof elf rel %ld\n",rela_plt_header->sh_entsize,sizeof(Elf64_Rel));
    int success = 0;

    LOGD("ioctl addr is %lx\n", ioctl);
    LOGD("dynstr sh_size : %llx \n sh_entsize : %llx \n offset : %llx\n",
         dynstr_header->sh_size, dynstr_header->sh_entsize, dynstr_header->sh_offset);
    for (int i = 0; i < rela_plt_header->sh_size / rela_plt_header->sh_entsize; ++i) {
        Elf64_Rela *rel_ent = rela_plt_tab+i;
        unsigned ndx = ELF_R_SYM(rel_ent->r_info);
        char *syn = dynstr + dynsymtab[ndx].st_name;
        //LOGD("%d %s %lx\n", ndx, syn, rel_ent->r_offset);
        if (strcmp(target_func_name, syn) == 0) {
            //LOGD("ndx = %d, str = %s  i = %d \n", ndx, dynstr + dynsymtab[ndx].st_name, i);
            result_offset = rela_plt_tab[i].r_offset;
            uint64_t target_func_addr = (uint64_t) (result_offset + bias);
            if (*(long *) target_func_addr == old_func) {
                //备份原来的ioctl
                old_ioctl = old_func;
                long *point = (long *) target_func_addr;
                mprotect((void *) PAGE_START(target_func_addr), PAGE_SIZE,
                         PROT_READ | PROT_WRITE);
                *point = new_func;
                //clear cache of code
                __builtin___clear_cache((char *) PAGE_START(target_func_addr),
                                        (char *) PAGE_END(target_func_addr));
                success = 1;
            }
            break;
        }
    }

    if (success) {
        LOGD("hook success\n");
    } else {
        LOGD("hook failed\n");
    }
    close_elf(elf_file);
}

int got_hook_ioctl() {
#if defined(__arm__)
    char *lib_binder_path = "/system/lib/libbinder.so";
#else
    char *lib_binder_path = "/system/lib64/libbinder.so";
#endif
    char *target_function_name = "ioctl";
    got_hook(lib_binder_path, target_function_name, ioctl, new_ioctl);
}
