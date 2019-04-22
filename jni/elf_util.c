//
// Created by egguncle on 2019/4/12.
//


#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <memory.h>
#include <errno.h>
#include "include/log.h"
#include "include/elf_util.h"

FILE *open_elf(char *path) {
    if (path != NULL) {
        LOGD("open lib %s\n", path);
        FILE *fp = fopen(path, "rb");
        if (fp == NULL) {
            LOGD("opendir: %s\n", strerror(errno));
        }
        return fp;
    }
    return NULL;
}

void close_elf(FILE *file) {
    if (file != NULL) {
        printf("Close ELF file\n");
        fclose(file);
    }
}

void parse_elf_header(Elf_Ehdr *elf_header, FILE *elf_file) {
    if (elf_header == NULL || elf_file == NULL) {
        LOGD("elf_header is null or elf_file is null");
        return;
    }
    fseek(elf_file, 0, SEEK_SET);
    fread(elf_header, sizeof(Elf_Ehdr), 1, elf_file);
}

char *parse_shstrtab_content(FILE *elf_file, Elf_Ehdr *elf_header) {
    off_t shstrtab_header_offset =
            elf_header->e_shoff + elf_header->e_shstrndx * sizeof(Elf_Ehdr);
    Elf_Shdr *shstrtab_header = (Elf_Shdr *) malloc(sizeof(Elf_Shdr));
    fseek(elf_file, shstrtab_header_offset, SEEK_SET);
    fread(shstrtab_header, sizeof(Elf_Shdr), 1, elf_file);
    Elf_Xword sh_size = shstrtab_header->sh_size;
    char *shstrtab_content = (char *) malloc(sh_size * sizeof(char));
    off_t shstrtab_base_offset = shstrtab_header->sh_offset;
    fseek(elf_file, shstrtab_base_offset, SEEK_SET);
    fread(shstrtab_content, sh_size, 1, elf_file);
    return shstrtab_content;
}

Elf_Shdr *parse_target_table_data(char *shstrtab_content, FILE *elf_file, Elf_Ehdr *elf_header,
                                  char *target_tab_name) {
    off_t base_offset = elf_header->e_shoff;
    Elf_Half e_shnum = elf_header->e_shnum;
    Elf_Shdr *tmp_header = (Elf_Shdr *) malloc(sizeof(Elf_Shdr));
    for (int i = 0; i < e_shnum; ++i) {
        fseek(elf_file, base_offset, SEEK_SET);
        fread(tmp_header, sizeof(Elf_Shdr), 1, elf_file);
        char *section_name = shstrtab_content + tmp_header->sh_name;
        if (strcmp(section_name, target_tab_name) == 0) {
            //  LOGD("%s\n", section_name);
            break;
        }
        base_offset += sizeof(Elf_Shdr);
    }
    return tmp_header;
}

long get_libs_addr(pid_t pid, char *lib_name) {
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
    return addr;
}

long get_segment_base_address(int fd, long base_addr, int phnum, size_t phsize,
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
