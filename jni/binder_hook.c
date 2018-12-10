
//
// Created by songyucheng on 18-11-9.
//

#include <fcntl.h>
#include <sys/ioctl.h>
#include "include/binder_hook.h"
#include "include/elf_util.h"
#include "include/binder.h"
#include "include/bind_hook_utils.h"

int (*old_ioctl)(int __fd, unsigned long int __request, void *arg);

int new_ioctl(int __fd, unsigned long int __request, void *arg) {
//./data/local/tmp/ptraceMain system_server hook_entry /data/local/tmp/libbinderhook-lib.so
//./data/local/tmp/ptraceMain com.android.phone hook_entry /data/local/tmp/libbinderhook-lib.so
//./data/local/tmp/ptraceMain com.test.gothooktest hook_entry /data/local/tmp/libbinderhook-lib.so
    if (__request == BINDER_WRITE_READ) {
        struct binder_write_read *tmp = (struct binder_write_read *) arg;
        binder_size_t read_size = tmp->read_size;
        binder_size_t write_size = tmp->write_size;
        LOGE("----------------------------------------------------------------\n");
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
                        hex_data_dump(pdata);
                    }
                        break;
                    case BR_REPLY: {
                        LOGE("read BR_REPLY");
                        hex_data_dump(pdata);
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
                        hex_data_dump(pdata);
                    }
                        break;
                    case BC_REPLY: {
                        LOGE("write BC_REPLY");
                        hex_data_dump(pdata);
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


int hook_entry() {

#if defined(__arm__)
    char *lib_binder_path = "/system/lib/libbinder.so";
#else
    char *lib_binder_path = "/system/lib64/libbinder.so";
#endif
    char *target_function_name = "ioctl";

    FILE *elf_file = open_elf_file(lib_binder_path);
    if (elf_file == NULL) {
        LOGD("elf file is null \n");
        return 0;
    }
    Elf_Ehdr *elf_header = (Elf_Ehdr *) malloc(sizeof(Elf_Ehdr));
    get_elf_header(elf_header, elf_file);
    if (elf_header == NULL) {
        LOGD("elf_head  is null \n");
        return 0;
    }

    int fd = open(lib_binder_path, O_RDONLY);
    long target_lib_base_addr = get_libs_addr(-1, lib_binder_path);
    LOGD("target base addr is %lx\n", target_lib_base_addr);
    //基址不一定是maps中的地址，当第一个PT_LOAD 的vaddr不为0的时候，需要进行额外的计算
    unsigned long phdr_addr = elf_header->e_phoff;//程序头表在文件中的偏移量
    int phnum = elf_header->e_phnum;//程序头表表项数目
    size_t phsize = elf_header->e_phentsize;//程序头表项的大小
    void *bias = get_segment_base_address(fd, target_lib_base_addr, phnum, phsize,
                                          phdr_addr);//获得该段的内存基址

    //read shstrtab content
    char *shstrtab_content = get_shstrtab_content(elf_file, elf_header);
    Elf_Shdr *dynsym_header = get_target_table_data(shstrtab_content, elf_file, elf_header,
                                                    ".dynsym");
    Elf_Shdr *dynstr_header = get_target_table_data(shstrtab_content, elf_file, elf_header,
                                                    ".dynstr");
    //read dynstr data
    char *dynstr = (char *) malloc(sizeof(char) * dynstr_header->sh_size);
    fseek(elf_file, dynstr_header->sh_offset, SEEK_SET);
    fread(dynstr, dynstr_header->sh_size, 1, elf_file);

    Elf_Sym *dynsymtab = (Elf_Sym *) malloc(dynsym_header->sh_size);
    //LOGD("dynsym_shdr->sh_size %x\n", dynsym_header->sh_size);
    fseek(elf_file, dynsym_header->sh_offset, SEEK_SET);
    fread(dynsymtab, dynsym_header->sh_size, 1, elf_file);

    long result_offset = 0;
    LOGD("try to find target func on rela.plt\n");
    //search target in rela.plt
    Elf_Shdr *rela_plt_header = get_target_table_data(shstrtab_content, elf_file, elf_header,
                                                      ".rela.plt");
    Elf_Rel *rela_plt_tab = (Elf_Sym *) malloc(rela_plt_header->sh_size);
    fseek(elf_file, rela_plt_header->sh_offset, SEEK_SET);
    fread(rela_plt_tab, rela_plt_header->sh_size, 1, elf_file);
//    LOGD("rela_plt_header->sh_size %x\n",
//         rela_plt_header->sh_size / rela_plt_header->sh_entsize);
    int success = 0;
    for (int i = 0; i < rela_plt_header->sh_size / rela_plt_header->sh_entsize; ++i) {
        Elf_Rel rel_ent = rela_plt_tab[i];
        unsigned ndx = ELF_R_SYM(rel_ent.r_info);
        char *syn = dynstr + dynsymtab[ndx].st_name;
        if (strcmp(target_function_name, syn) == 0) {
            //LOGD("ndx = %d, str = %s  i = %d \n", ndx, dynstr + dynsymtab[ndx].st_name, i);
            result_offset = rela_plt_tab[i].r_offset;

            uint64_t target_func_addr = (uint64_t) (result_offset + bias);
//            LOGD("target func addr %lx\n", target_func_addr);
//            LOGD("target func addr point %lx\n", *(long *) target_func_addr);
            if (*(long *) target_func_addr == ioctl) {
                //备份原来的ioctl
                old_ioctl = (int (*)(int, unsigned long, void *)) ioctl;

                long *point = (long *) target_func_addr;
                mprotect((void *) PAGE_START(target_func_addr), PAGE_SIZE,
                         PROT_READ | PROT_WRITE);
                *point = new_ioctl;
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


    close_elf_file(elf_file);
    return 0;

}