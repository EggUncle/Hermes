#include <stdio.h>
#include <elf.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <malloc.h>
#include <sys/mman.h>
#include <sys/user.h>
#include<android/log.h>
#include "binder_hook.h"


#if defined(__arm__)
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Shdr Elf32_Shdr
#define Elf_Phdr Elf32_Phdr
#define Elf_Sym Elf32_Sym
#define Elf_Rel Elf32_Rel
#define Elf_Xword Elf32_Word
#define Elf_Half Elf32_Half
#define Elf_Off Elf32_Off
#define ELF_R_SYM ELF32_R_SYM
#else
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Shdr Elf64_Shdr
#define Elf_Phdr Elf64_Phdr
#define Elf_Sym Elf64_Sym
#define Elf_Rel Elf64_Rel
#define Elf_Xword Elf64_Xword
#define Elf_Half Elf64_Half
#define Elf_Off Elf64_Off
#define ELF_R_SYM ELF64_R_SYM
#endif

#define PAGE_START(addr) ((addr) & PAGE_MASK)
#define PAGE_END(addr)   (PAGE_START(addr) + PAGE_SIZE)

FILE *open_elf_file(char *library_path);

void close_elf_file(FILE *elf_file);

void get_elf_header(Elf_Ehdr *elf_header, FILE *elf_file);

char *get_shstrtab_content(FILE *elf_file, Elf_Ehdr *elf_header);

Elf_Shdr *get_target_table_data(char *shstrtab_content, FILE *elf_file, Elf_Ehdr *elf_header,
                                char *target_tab_name);
