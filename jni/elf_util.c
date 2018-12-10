//
// Created by songyucheng on 18-11-1.
//


#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include "include/elf_util.h"
#include "include/bind_hook_utils.h"


FILE *open_elf_file(char *library_path) {
    if (library_path != NULL) {
        LOGD("open lib %s\n", library_path);
        FILE *fp = fopen(library_path, "rb");
        if (fp == NULL) {
            LOGD("opendir: %s\n", strerror(errno));
        }
        return fp;
    }
    return NULL;
}

void close_elf_file(FILE *elf_file) {
    if (elf_file != NULL) {
        printf("Close ELF file\n");
        fclose(elf_file);
    }
}

void get_elf_header(Elf_Ehdr *elf_header, FILE *elf_file) {
    if (elf_header == NULL || elf_file == NULL) {
        LOGD("elf_header is null or elf_file is null");
        return;
    }
    fseek(elf_file, 0, SEEK_SET);
    fread(elf_header, sizeof(Elf_Ehdr), 1, elf_file);
}

char *get_shstrtab_content(FILE *elf_file, Elf_Ehdr *elf_header) {
    off_t shstrtab_header_offset =
            elf_header->e_shoff + elf_header->e_shstrndx * sizeof(Elf_Ehdr);
    LOGD("elf e_shstrndx offset is %lx \n", shstrtab_header_offset);
    Elf_Shdr *shstrtab_header = (Elf_Shdr *) malloc(sizeof(Elf_Shdr));
    fseek(elf_file, shstrtab_header_offset, SEEK_SET);
    fread(shstrtab_header, sizeof(Elf_Shdr), 1, elf_file);
    Elf_Xword sh_size = shstrtab_header->sh_size;
    LOGD("shstrndx size is %d \n", sh_size);
    char *shstrtab_content = (char *) malloc(sh_size * sizeof(char));
    off_t shstrtab_base_offset = shstrtab_header->sh_offset;
    LOGD("shstrndx shstrtab_base_offset is %lx \n", shstrtab_base_offset);
    fseek(elf_file, shstrtab_base_offset, SEEK_SET);
    fread(shstrtab_content, sh_size, 1, elf_file);
    LOGD("%s\n", shstrtab_content + shstrtab_header->sh_name);
    LOGD("--------------\n");
    return shstrtab_content;
}


Elf_Shdr *
get_target_table_data(char *shstrtab_content, FILE *elf_file, Elf_Ehdr *elf_header,
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

