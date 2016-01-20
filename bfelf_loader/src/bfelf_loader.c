/*
 * Bareflank Hypervisor
 *
 * Copyright (C) 2015 Assured Information Security, Inc.
 * Author: Rian Quinn        <quinnr@ainfosec.com>
 * Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <bfelf_loader.h>

#ifdef ENABLE_BFELF_DEBUGGING
#ifndef BFELF_PRINTF
#include <stdio.h>
#define BFELF_PRINTF printf
#endif
#define DEBUG(...) BFELF_PRINTF("[ELF DEBUG]: " __VA_ARGS__)
#define INFO(...) BFELF_PRINTF(__VA_ARGS__)
#else
#define DEBUG(...)
#define INFO(...)
#endif

#ifdef LINUX_KERNEL
#include <linux/module.h>
#define ALERT(...) printk("[ELF ALERT]: " __VA_ARGS__)
#else
#include <stdio.h>
#define ALERT(...) printf("[ELF ALERT]: " __VA_ARGS__)
#endif

/******************************************************************************/
/* ELF Helpers                                                                */
/******************************************************************************/

bfelf64_sword
bfelf_strcmp(struct e_string_t *str1, struct e_string_t *str2)
{
    bfelf64_sword i = 0;

    if (!str1 || !str2)
        return BFELF_ERROR_INVALID_ARG;

    if (str1->len != str2->len)
        return BFELF_FALSE;

    for (i = 0; i < str1->len && i < str2->len; i++)
    {
        if (str1->buf[i] != str2->buf[i])
            return BFELF_FALSE;

        if (str1->buf[i] == 0 ||
            str2->buf[i] == 0)
        {
            return BFELF_ERROR_INVALID_STRING;
        }
    }

    return BFELF_TRUE;
}

/******************************************************************************/
/* ELF Error Codes                                                            */
/******************************************************************************/

const char *BFELF_SUCCESS_STR = "Success (BFELF_SUCCESS)";
const char *BFELF_ERROR_INVALID_ARG_STR = "Invalid argument (BFELF_ERROR_INVALID_ARG)";
const char *BFELF_ERROR_INVALID_FILE_STR = "Invalid elf file (BFELF_ERROR_INVALID_FILE)";
const char *BFELF_ERROR_INVALID_INDEX_STR = "Invalid index (BFELF_ERROR_INVALID_INDEX)";
const char *BFELF_ERROR_INVALID_OFFSET_STR = "Invalid offset (BFELF_ERROR_INVALID_OFFSET)";
const char *BFELF_ERROR_INVALID_STRING_STR = "Invliad string (BFELF_ERROR_INVALID_STRING)";
const char *BFELF_ERROR_INVALID_EI_MAG0_STR = "Invalid magic number (0) in elf header (BFELF_ERROR_INVALID_EI_MAG0)";
const char *BFELF_ERROR_INVALID_EI_MAG1_STR = "Invalid magic number (1) in elf header (BFELF_ERROR_INVALID_EI_MAG1)";
const char *BFELF_ERROR_INVALID_EI_MAG2_STR = "Invalid magic number (2) in elf header (BFELF_ERROR_INVALID_EI_MAG2)";
const char *BFELF_ERROR_INVALID_EI_MAG3_STR = "Invalid magic number (3) in elf header (BFELF_ERROR_INVALID_EI_MAG3)";
const char *BFELF_ERROR_INVALID_EI_CLASS_STR = "Invalid class field in elf header (BFELF_ERROR_INVALID_EI_CLASS)";
const char *BFELF_ERROR_INVALID_EI_DATA_STR = "Invalid data field in elf header (BFELF_ERROR_INVALID_EI_DATA)";
const char *BFELF_ERROR_INVALID_EI_VERSION_STR = "Invalid version in elf header (BFELF_ERROR_INVALID_EI_VERSION)";
const char *BFELF_ERROR_INVALID_EI_OSABI_STR = "Invalid OS/ABI field in elf header (BFELF_ERROR_INVALID_EI_OSABI)";
const char *BFELF_ERROR_INVALID_EI_ABIVERSION_STR = "Invalid ABI version in elf header (BFELF_ERROR_INVALID_EI_ABIVERSION)";
const char *BFELF_ERROR_INVALID_E_TYPE_STR = "Invalid type field in elf header (BFELF_ERROR_INVALID_E_TYPE)";
const char *BFELF_ERROR_INVALID_E_MACHINE_STR = "Invalid machine ID in elf header (BFELF_ERROR_INVALID_E_MACHINE)";
const char *BFELF_ERROR_INVALID_E_ENTRY_STR = "Invalid entry point in elf header (BFELF_ERROR_INVALID_E_ENTRY)";
const char *BFELF_ERROR_INVALID_E_PHOFF_STR = "Invalid program header offset in elf header (BFELF_ERROR_INVALID_E_PHOFF)";
const char *BFELF_ERROR_INVALID_E_SHOFF_STR = "Invalid section header offset in elf header (BFELF_ERROR_INVALID_E_SHOFF)";
const char *BFELF_ERROR_INVALID_E_FLAGS_STR = "Invalid flags in elf header (BFELF_ERROR_INVALID_E_FLAGS)";
const char *BFELF_ERROR_INVALID_E_EHSIZE_STR = "Invalid header size in elf header (BFELF_ERROR_INVALID_E_EHSIZE)";
const char *BFELF_ERROR_INVALID_E_PHENTSIZE_STR = "Invalid program entry header size in elf header (BFELF_ERROR_INVALID_E_PHENTSIZE)";
const char *BFELF_ERROR_INVALID_E_PHNUM_STR = "Invalid number of program entries in elf header (BFELF_ERROR_INVALID_E_PHNUM)";
const char *BFELF_ERROR_INVALID_E_SHENTSIZE_STR = "Invalid section header size in elf header (BFELF_ERROR_INVALID_E_SHENTSIZE)";
const char *BFELF_ERROR_INVALID_E_SHNUM_STR = "Invalid number of section entries in elf header (BFELF_ERROR_INVALID_E_SHNUM)";
const char *BFELF_ERROR_INVALID_E_SHSTRNDX_STR = "Invalid section name string index table in elf header (BFELF_ERROR_INVALID_E_SHSTRNDX)";
const char *BFELF_ERROR_INVALID_PHT_STR = "Invalid program header table (BFELF_ERROR_INVALID_PHT)";
const char *BFELF_ERROR_INVALID_SHT_STR = "Invalid section header table (BFELF_ERROR_INVALID_SHT)";
const char *BFELF_ERROR_INVALID_SH_NAME_STR = "Invalid section name (BFELF_ERROR_INVALID_SH_NAME)";
const char *BFELF_ERROR_INVALID_SH_TYPE_STR = "Invalid section type (BFELF_ERROR_INVALID_SH_TYPE)";
const char *BFELF_ERROR_INVALID_SH_FLAGS_STR = "Invalid section flags (BFELF_ERROR_INVALID_SH_FLAGS)";
const char *BFELF_ERROR_INVALID_SH_ADDR_STR = "Invalid section address (BFELF_ERROR_INVALID_SH_ADDR)";
const char *BFELF_ERROR_INVALID_SH_OFFSET_STR = "Invalid section offset (BFELF_ERROR_INVALID_SH_OFFSET)";
const char *BFELF_ERROR_INVALID_SH_SIZE_STR = "Invalid section size (BFELF_ERROR_INVALID_SH_SIZE)";
const char *BFELF_ERROR_INVALID_SH_LINK_STR = "Invalid section link (BFELF_ERROR_INVALID_SH_LINK)";
const char *BFELF_ERROR_INVALID_SH_INFO_STR = "Invalid section info (BFELF_ERROR_INVALID_SH_INFO)";
const char *BFELF_ERROR_INVALID_SH_ADDRALIGN_STR = "Invalid section address alignment (BFELF_ERROR_INVALID_SH_ADDRALIGN)";
const char *BFELF_ERROR_INVALID_SH_ENTSIZE_STR = "Invalid section entry size (BFELF_ERROR_INVALID_SH_ENTSIZE)";
const char *BFELF_ERROR_INVALID_PH_TYPE_STR = "Invalid segment type (BFELF_ERROR_INVALID_PH_TYPE)";
const char *BFELF_ERROR_INVALID_PH_FLAGS_STR = "Invalid segment flags (BFELF_ERROR_INVALID_PH_FLAGS)";
const char *BFELF_ERROR_INVALID_PH_OFFSET_STR = "Invalid segment offset (BFELF_ERROR_INVALID_PH_OFFSET)";
const char *BFELF_ERROR_INVALID_PH_VADDR_STR = "Invalid segment vaddr (BFELF_ERROR_INVALID_PH_VADDR)";
const char *BFELF_ERROR_INVALID_PH_PADDR_STR = "Invalid segment paddr (BFELF_ERROR_INVALID_PH_PADDR)";
const char *BFELF_ERROR_INVALID_PH_FILESZ_STR = "Invalid segment file size (BFELF_ERROR_INVALID_PH_FILESZ)";
const char *BFELF_ERROR_INVALID_PH_MEMSZ_STR = "Invalid segment mem size (BFELF_ERROR_INVALID_PH_MEMSZ)";
const char *BFELF_ERROR_INVALID_PH_ALIGN_STR = "Invalid segment alignment (BFELF_ERROR_INVALID_PH_ALIGN)";
const char *BFELF_ERROR_INVALID_STRING_TABLE_STR = "Invalid string table (BFELF_ERROR_INVALID_STRING_TABLE)";
const char *BFELF_ERROR_NO_SUCH_SYMBOL_STR = "Unable to find symbol (BFELF_ERROR_NO_SUCH_SYMBOL)";
const char *BFELF_ERROR_SYMBOL_UNDEFINED_STR = "Symbol is undefined (BFELF_ERROR_SYMBOL_UNDEFINED)";
const char *BFELF_ERROR_LOADER_FULL_STR = "Loader is full (BFELF_ERROR_LOADER_FULL_STR)";
const char *BFELF_ERROR_INVALID_LOADER_STR = "Invalid loader (BFELF_ERROR_INVALID_LOADER)";
const char *BFELF_ERROR_INVALID_RELOCATION_TYPE_STR = "Invalid relocation type (BFELF_ERROR_INVALID_RELOCATION_TYPE)";

const char *
bfelf_error(bfelf64_sword value)
{
    switch (value)
    {
        case BFELF_SUCCESS: return BFELF_SUCCESS_STR;
        case BFELF_ERROR_INVALID_ARG: return BFELF_ERROR_INVALID_ARG_STR;
        case BFELF_ERROR_INVALID_FILE: return BFELF_ERROR_INVALID_FILE_STR;
        case BFELF_ERROR_INVALID_INDEX: return BFELF_ERROR_INVALID_INDEX_STR;
        case BFELF_ERROR_INVALID_OFFSET: return BFELF_ERROR_INVALID_OFFSET_STR;
        case BFELF_ERROR_INVALID_STRING: return BFELF_ERROR_INVALID_STRING_STR;
        case BFELF_ERROR_INVALID_EI_MAG0: return BFELF_ERROR_INVALID_EI_MAG0_STR;
        case BFELF_ERROR_INVALID_EI_MAG1: return BFELF_ERROR_INVALID_EI_MAG1_STR;
        case BFELF_ERROR_INVALID_EI_MAG2: return BFELF_ERROR_INVALID_EI_MAG2_STR;
        case BFELF_ERROR_INVALID_EI_MAG3: return BFELF_ERROR_INVALID_EI_MAG3_STR;
        case BFELF_ERROR_INVALID_EI_CLASS: return BFELF_ERROR_INVALID_EI_CLASS_STR;
        case BFELF_ERROR_INVALID_EI_DATA: return BFELF_ERROR_INVALID_EI_DATA_STR;
        case BFELF_ERROR_INVALID_EI_VERSION: return BFELF_ERROR_INVALID_EI_VERSION_STR;
        case BFELF_ERROR_INVALID_EI_OSABI: return BFELF_ERROR_INVALID_EI_OSABI_STR;
        case BFELF_ERROR_INVALID_EI_ABIVERSION: return BFELF_ERROR_INVALID_EI_ABIVERSION_STR;
        case BFELF_ERROR_INVALID_E_TYPE: return BFELF_ERROR_INVALID_E_TYPE_STR;
        case BFELF_ERROR_INVALID_E_MACHINE: return BFELF_ERROR_INVALID_E_MACHINE_STR;
        case BFELF_ERROR_INVALID_E_ENTRY: return BFELF_ERROR_INVALID_E_ENTRY_STR;
        case BFELF_ERROR_INVALID_E_PHOFF: return BFELF_ERROR_INVALID_E_PHOFF_STR;
        case BFELF_ERROR_INVALID_E_SHOFF: return BFELF_ERROR_INVALID_E_SHOFF_STR;
        case BFELF_ERROR_INVALID_E_FLAGS: return BFELF_ERROR_INVALID_E_FLAGS_STR;
        case BFELF_ERROR_INVALID_E_EHSIZE: return BFELF_ERROR_INVALID_E_EHSIZE_STR;
        case BFELF_ERROR_INVALID_E_PHENTSIZE: return BFELF_ERROR_INVALID_E_PHENTSIZE_STR;
        case BFELF_ERROR_INVALID_E_PHNUM: return BFELF_ERROR_INVALID_E_PHNUM_STR;
        case BFELF_ERROR_INVALID_E_SHENTSIZE: return BFELF_ERROR_INVALID_E_SHENTSIZE_STR;
        case BFELF_ERROR_INVALID_E_SHNUM: return BFELF_ERROR_INVALID_E_SHNUM_STR;
        case BFELF_ERROR_INVALID_E_SHSTRNDX: return BFELF_ERROR_INVALID_E_SHSTRNDX_STR;
        case BFELF_ERROR_INVALID_PHT: return BFELF_ERROR_INVALID_PHT_STR;
        case BFELF_ERROR_INVALID_SHT: return BFELF_ERROR_INVALID_SHT_STR;
        case BFELF_ERROR_INVALID_SH_NAME: return BFELF_ERROR_INVALID_SH_NAME_STR;
        case BFELF_ERROR_INVALID_SH_TYPE: return BFELF_ERROR_INVALID_SH_TYPE_STR;
        case BFELF_ERROR_INVALID_SH_FLAGS: return BFELF_ERROR_INVALID_SH_FLAGS_STR;
        case BFELF_ERROR_INVALID_SH_ADDR: return BFELF_ERROR_INVALID_SH_ADDR_STR;
        case BFELF_ERROR_INVALID_SH_OFFSET: return BFELF_ERROR_INVALID_SH_OFFSET_STR;
        case BFELF_ERROR_INVALID_SH_SIZE: return BFELF_ERROR_INVALID_SH_SIZE_STR;
        case BFELF_ERROR_INVALID_SH_LINK: return BFELF_ERROR_INVALID_SH_LINK_STR;
        case BFELF_ERROR_INVALID_SH_INFO: return BFELF_ERROR_INVALID_SH_INFO_STR;
        case BFELF_ERROR_INVALID_SH_ADDRALIGN: return BFELF_ERROR_INVALID_SH_ADDRALIGN_STR;
        case BFELF_ERROR_INVALID_SH_ENTSIZE: return BFELF_ERROR_INVALID_SH_ENTSIZE_STR;
        case BFELF_ERROR_INVALID_PH_TYPE: return BFELF_ERROR_INVALID_PH_TYPE_STR;
        case BFELF_ERROR_INVALID_PH_FLAGS: return BFELF_ERROR_INVALID_PH_FLAGS_STR;
        case BFELF_ERROR_INVALID_PH_OFFSET: return BFELF_ERROR_INVALID_PH_OFFSET_STR;
        case BFELF_ERROR_INVALID_PH_VADDR: return BFELF_ERROR_INVALID_PH_VADDR_STR;
        case BFELF_ERROR_INVALID_PH_PADDR: return BFELF_ERROR_INVALID_PH_PADDR_STR;
        case BFELF_ERROR_INVALID_PH_FILESZ: return BFELF_ERROR_INVALID_PH_FILESZ_STR;
        case BFELF_ERROR_INVALID_PH_MEMSZ: return BFELF_ERROR_INVALID_PH_MEMSZ_STR;
        case BFELF_ERROR_INVALID_PH_ALIGN: return BFELF_ERROR_INVALID_PH_ALIGN_STR;
        case BFELF_ERROR_INVALID_STRING_TABLE: return BFELF_ERROR_INVALID_STRING_TABLE_STR;
        case BFELF_ERROR_NO_SUCH_SYMBOL: return BFELF_ERROR_NO_SUCH_SYMBOL_STR;
        case BFELF_ERROR_SYMBOL_UNDEFINED: return BFELF_ERROR_SYMBOL_UNDEFINED_STR;
        case BFELF_ERROR_LOADER_FULL: return BFELF_ERROR_LOADER_FULL_STR;
        case BFELF_ERROR_INVALID_LOADER: return BFELF_ERROR_INVALID_LOADER_STR;
        default: return "Undefined";
    }
}

/******************************************************************************/
/* ELF File                                                                   */
/******************************************************************************/

bfelf64_sword
bfelf_file_init(char *file, uint64_t fsize, struct bfelf_file_t *ef)
{
    bfelf64_word i = 0;
    bfelf64_sword ret = 0;
    struct bfelf_shdr *dynsym = 0;
    struct bfelf_shdr *strtab = 0;
    struct bfelf_shdr *shstrtab = 0;

    if (!file || !ef)
        return BFELF_ERROR_INVALID_ARG;

    for (i = 0; i < sizeof(struct bfelf_file_t); i++)
        ((char *)ef)[i] = 0;

    if (fsize < sizeof(struct bfelf64_ehdr))
        return BFELF_ERROR_INVALID_ARG;

    ef->ehdr = (struct bfelf64_ehdr *)file;

    if (ef->ehdr->e_ident[bfei_mag0] != 0x7F)
        return BFELF_ERROR_INVALID_EI_MAG0;

    if (ef->ehdr->e_ident[bfei_mag1] != 'E')
        return BFELF_ERROR_INVALID_EI_MAG1;

    if (ef->ehdr->e_ident[bfei_mag2] != 'L')
        return BFELF_ERROR_INVALID_EI_MAG2;

    if (ef->ehdr->e_ident[bfei_mag3] != 'F')
        return BFELF_ERROR_INVALID_EI_MAG3;

    if (ef->ehdr->e_ident[bfei_class] != bfelfclass64)
        return BFELF_ERROR_INVALID_EI_CLASS;

    if (ef->ehdr->e_ident[bfei_data] != bfelfdata2lsb)
        return BFELF_ERROR_INVALID_EI_DATA;

    if (ef->ehdr->e_ident[bfei_version] != bfev_current)
        return BFELF_ERROR_INVALID_EI_VERSION;

    if (ef->ehdr->e_ident[bfei_osabi] != bfelfosabi_sysv)
        return BFELF_ERROR_INVALID_EI_OSABI;

    if (ef->ehdr->e_ident[bfei_abiversion] != 0)
        return BFELF_ERROR_INVALID_EI_ABIVERSION;

    if (ef->ehdr->e_type != bfet_dyn)
        return BFELF_ERROR_INVALID_E_TYPE;

    if (ef->ehdr->e_machine != bfem_x86_64)
        return BFELF_ERROR_INVALID_E_MACHINE;

    if (ef->ehdr->e_version != bfev_current)
        return BFELF_ERROR_INVALID_EI_VERSION;

    if (ef->ehdr->e_entry <= 0 ||
        ef->ehdr->e_entry >= fsize)
    {
        return BFELF_ERROR_INVALID_E_ENTRY;
    }

    if (ef->ehdr->e_phoff <= 0 ||
        ef->ehdr->e_phoff >= fsize)
    {
        return BFELF_ERROR_INVALID_E_PHOFF;
    }

    if (ef->ehdr->e_shoff <= 0 ||
        ef->ehdr->e_shoff >= fsize)
    {
        return BFELF_ERROR_INVALID_E_SHOFF;
    }

    if (ef->ehdr->e_flags != 0)
        return BFELF_ERROR_INVALID_E_FLAGS;

    if (ef->ehdr->e_ehsize != sizeof(struct bfelf64_ehdr))
        return BFELF_ERROR_INVALID_E_EHSIZE;

    if (ef->ehdr->e_phentsize != sizeof(struct bfelf_phdr))
        return BFELF_ERROR_INVALID_E_PHENTSIZE;

    if (ef->ehdr->e_shentsize != sizeof(struct bfelf_shdr))
        return BFELF_ERROR_INVALID_E_SHENTSIZE;

    if (ef->ehdr->e_shstrndx >= ef->ehdr->e_shnum)
        return BFELF_ERROR_INVALID_E_SHSTRNDX;

    if (ef->ehdr->e_shoff + (ef->ehdr->e_shentsize * ef->ehdr->e_shnum) > fsize)
        return BFELF_ERROR_INVALID_SHT;

    if (ef->ehdr->e_phoff + (ef->ehdr->e_phentsize * ef->ehdr->e_phnum) > fsize)
        return BFELF_ERROR_INVALID_PHT;

    ef->file = file;
    ef->fsize = fsize;
    ef->shdrtab = (struct bfelf_shdr *)(file + ef->ehdr->e_shoff);
    ef->phdrtab = (struct bfelf_phdr *)(file + ef->ehdr->e_phoff);

    for (i = 0; i < ef->ehdr->e_shnum; i++)
    {
        struct bfelf_shdr *shdr;

        ret = bfelf_section_header(ef, i, &shdr);
        if (ret != BFELF_SUCCESS)
            return ret;

        if (shdr->sh_type == bfsht_nobits)
            continue;

        if (shdr->sh_offset + shdr->sh_size > ef->fsize)
            return BFELF_ERROR_INVALID_SH_SIZE;
    }

    for (i = 0; i < ef->ehdr->e_phnum; i++)
    {
        struct bfelf_phdr *phdr;

        ret = bfelf_program_header(ef, i, &phdr);
        if (ret != BFELF_SUCCESS)
            return ret;

        if (phdr->p_offset + phdr->p_filesz > ef->fsize)
            return BFELF_ERROR_INVALID_PH_FILESZ;

        if (phdr->p_filesz > phdr->p_memsz)
            return BFELF_ERROR_INVALID_PH_FILESZ;
    }

    for (i = 0; i < ef->ehdr->e_shnum; i++)
    {
        struct bfelf_shdr *shdr;

        ret = bfelf_section_header(ef, i, &shdr);
        if (ret != BFELF_SUCCESS)
            return ret;

        if (shdr->sh_type == bfsht_dynsym)
        {
            dynsym = shdr;
            break;
        }
    }

    if (dynsym == 0)
        return BFELF_ERROR_INVALID_FILE;

    ret = bfelf_section_header(ef, dynsym->sh_link, &strtab);
    if (ret != BFELF_SUCCESS)
        return ret;

    if (strtab->sh_type != bfsht_strtab)
        return BFELF_ERROR_INVALID_SH_TYPE;

    ret = bfelf_section_header(ef, ef->ehdr->e_shstrndx, &shstrtab);
    if (ret != BFELF_SUCCESS)
        return ret;

    if (shstrtab->sh_type != bfsht_strtab)
        return BFELF_ERROR_INVALID_SH_TYPE;

    ef->dynsym = dynsym;
    ef->strtab = strtab;
    ef->shstrtab = shstrtab;

    ef->symnum = dynsym->sh_size / sizeof(struct bfelf_sym);
    ef->symtab = (struct bfelf_sym *)(file + dynsym->sh_offset);

    for (i = 0; i < ef->ehdr->e_shnum; i++)
    {
        struct bfelf_shdr *shdr;

        ret = bfelf_section_header(ef, i, &shdr);
        if (ret != BFELF_SUCCESS)
            return ret;

        if (shdr->sh_type == bfsht_rel)
        {
            ef->bfreltab[ef->num_rel].num = shdr->sh_size / sizeof(struct bfelf_rel);
            ef->bfreltab[ef->num_rel].tab = (struct bfelf_rel *)(ef->file + shdr->sh_offset);
            ef->num_rel++;
        }

        if (shdr->sh_type == bfsht_rela)
        {
            ef->bfrelatab[ef->num_rela].num = shdr->sh_size / sizeof(struct bfelf_rela);
            ef->bfrelatab[ef->num_rela].tab = (struct bfelf_rela *)(ef->file + shdr->sh_offset);
            ef->num_rela++;
        }
    }

    ef->valid = BFELF_TRUE;

    for (i = 0; i < ef->ehdr->e_shnum; i++)
    {
        struct bfelf_shdr *shdr;

        struct e_string_t name;
        struct e_string_t name_ctors = {".ctors", 6};
        struct e_string_t name_dtors = {".dtors", 6};
        struct e_string_t name_init_array = {".init_array", 11};
        struct e_string_t name_fini_array = {".fini_array", 11};

        ret = bfelf_section_header(ef, i, &shdr);
        if (ret != BFELF_SUCCESS)
            return ret;

        ret = bfelf_section_name_string(ef, shdr, &name);
        if (ret != BFELF_SUCCESS)
            return ret;

        if (bfelf_strcmp(&name, &name_ctors) == BFELF_TRUE)
        {
            ef->ctors = shdr;
            continue;
        }

        if (bfelf_strcmp(&name, &name_dtors) == BFELF_TRUE)
        {
            ef->dtors = shdr;
            continue;
        }

        if (bfelf_strcmp(&name, &name_init_array) == BFELF_TRUE)
        {
            ef->init_array = shdr;
            continue;
        }

        if (bfelf_strcmp(&name, &name_fini_array) == BFELF_TRUE)
        {
            ef->fini_array = shdr;
            continue;
        }
    }

    return BFELF_SUCCESS;
}

bfelf64_sword
bfelf_file_load(struct bfelf_file_t *ef, char *exec, uint64_t esize)
{
    bfelf64_word i = 0;
    bfelf64_sword ret = 0;
    bfelf64_sword total_size = 0;

    if (!ef || !exec)
        return BFELF_ERROR_INVALID_ARG;

    if (ef->valid != BFELF_TRUE)
        return BFELF_ERROR_INVALID_FILE;

    total_size = bfelf_total_exec_size(ef);
    if (total_size < BFELF_SUCCESS)
        return ret;

    if ((bfelf64_sword)esize != total_size)
        return BFELF_ERROR_INVALID_ARG;

    for (i = 0; i < esize; i++)
        exec[i] = 0;

    ef->exec = exec;
    ef->esize = esize;

    ret = bfelf_load_segments(ef);
    if (ret != BFELF_SUCCESS)
        return ret;

    /* TODO: Make sure there are no duplicate symbols */

    return BFELF_SUCCESS;
}

/******************************************************************************/
/* ELF Loader                                                                 */
/******************************************************************************/

bfelf64_sword
bfelf_loader_init(struct bfelf_loader_t *loader)
{
    bfelf64_word i = 0;

    if (!loader)
        return BFELF_ERROR_INVALID_ARG;

    for (i = 0; i < sizeof(struct bfelf_loader_t); i++)
        ((char *)loader)[i] = 0;

    return BFELF_SUCCESS;
}

bfelf64_sword
bfelf_loader_add(struct bfelf_loader_t *loader, struct bfelf_file_t *ef)
{
    if (!loader || !ef)
        return BFELF_ERROR_INVALID_ARG;

    if (loader->num >= BFELF_MAX_MODULES)
        return BFELF_ERROR_LOADER_FULL;

    if (ef->valid != BFELF_TRUE)
        return BFELF_ERROR_INVALID_FILE;

    loader->efs[loader->num++] = ef;

    return BFELF_SUCCESS;
}

bfelf64_sword
bfelf_loader_relocate(struct bfelf_loader_t *loader)
{
    bfelf64_sword i = 0;
    bfelf64_sword j = 0;
    bfelf64_sword ret = 0;

    if (!loader)
        return BFELF_ERROR_INVALID_ARG;

    if (loader->num > BFELF_MAX_MODULES)
        return BFELF_ERROR_INVALID_LOADER;

    for (i = 0; i < loader->num; i++)
    {
        struct bfelf_file_t *ef1 = loader->efs[i];

        for (j = 0; j < BFELF_MAX_MODULES; j++)
            ef1->eftab[j] = 0;

        for (j = 0; j < loader->num; j++)
        {
            struct bfelf_file_t *ef2 = loader->efs[j];

            if (ef1 == ef2)
                continue;

            ef1->eftab[ef1->efnum++] = ef2;
        }

        ret = bfelf_relocate_symbols(ef1);
        if (ret != BFELF_SUCCESS)
            return ret;
    }

    /* TODO: Make sure there are no duplicate symbols globally */

    return BFELF_SUCCESS;
}

/******************************************************************************/
/* ELF File Header                                                            */
/******************************************************************************/

const char *bfelfclass32_str = "ELF32 (bfelfclass32)";
const char *bfelfclass64_str = "ELF64 (bfelfclass64)";

const char *
ei_class_to_str(unsigned char value)
{
    switch (value)
    {
        case bfelfclass32: return bfelfclass32_str;
        case bfelfclass64: return bfelfclass64_str;
        default: return "Unknown bfei_class";
    }
}

const char *bfelfdata2lsb_str = "2's complement, little endian (bfelfdata2lsb)";
const char *bfelfdata2msb_str = "2's complement, big endian (bfelfdata2msb)";

const char *
ei_data_to_str(unsigned char value)
{
    switch (value)
    {
        case bfelfdata2lsb: return bfelfdata2lsb_str;
        case bfelfdata2msb: return bfelfdata2msb_str;
        default: return "Unknown bfei_data";
    }
}

const char *
version_to_str(unsigned char value)
{
    switch (value)
    {
        case bfev_current: return "1 (bfev_current)";
        default: return "Unknown version";
    }
}

const char *bfelfosabi_sysv_str = "System V ABI (bfelfosabi_sysv)";
const char *bfelfosabi_hpux_str = "HP-UX operating system (bfelfosabi_hpux)";
const char *bfelfosabi_standalone_str = "Standalone (bfelfosabi_standalone)";

const char *
ei_osabi_to_str(unsigned char value)
{
    switch (value)
    {
        case bfelfosabi_sysv: return bfelfosabi_sysv_str;
        case bfelfosabi_hpux: return bfelfosabi_hpux_str;
        case bfelfosabi_standalone: return bfelfosabi_standalone_str;
        default: return "Unknown bfei_osabi";
    }
}

const char *bfet_none_str = "No file type (bfet_none)";
const char *bfet_rel_str = "Relocatable object file (bfet_rel)";
const char *bfet_exec_str = "Executable file (bfet_exec)";
const char *bfet_dyn_str = "Shared object file (bfet_dyn)";
const char *bfet_core_str = "Core file (bfet_core)";
const char *bfet_loos_str = "Environment-specific use (bfet_loos)";
const char *bfet_hios_str = "Environment-specific use (bfet_hios)";
const char *bfet_loproc_str = "Processor-specific use (bfet_loproc)";
const char *bfet_hiproc_str = "Processor-specific use (bfet_hiproc)";

const char *
e_type_to_str(bfelf64_half value)
{
    switch (value)
    {
        case bfet_none: return bfet_none_str;
        case bfet_rel: return bfet_rel_str;
        case bfet_exec: return bfet_exec_str;
        case bfet_dyn: return bfet_dyn_str;
        case bfet_core: return bfet_core_str;
        case bfet_loos: return bfet_loos_str;
        case bfet_hios: return bfet_hios_str;
        case bfet_loproc: return bfet_loproc_str;
        case bfet_hiproc: return bfet_hiproc_str;
        default: return "Unknown bfe_type";
    }
}

const char *bfem_none_str = "none";
const char *bfem_m32_str = "m32";
const char *bfem_sparc_str = "sparc";
const char *bfem_386_str = "386";
const char *bfem_68k_str = "68k";
const char *bfem_88k_str = "88k";
const char *bfem_486_str = "486";
const char *bfem_860_str = "860";
const char *bfem_mips_str = "mips";
const char *bfem_mips_rs3_le_str = "mips_rs3_le";
const char *bfem_mips_rs4_be_str = "mips_rs4_be";
const char *bfem_parisc_str = "parisc";
const char *bfem_sparc32plus_str = "sparc32plus";
const char *bfem_ppc_str = "ppc";
const char *bfem_ppc64_str = "ppc64";
const char *bfem_spu_str = "spu";
const char *bfem_arm_str = "arm";
const char *bfem_sh_str = "sh";
const char *bfem_sparcv9_str = "sparcv9";
const char *bfem_h8_300_str = "h8_300";
const char *bfem_ia_64_str = "ia_64";
const char *bfem_x86_64_str = "x86_64";
const char *bfem_s390_str = "s390";
const char *bfem_cris_str = "cris";
const char *bfem_v850_str = "v850";
const char *bfem_m32r_str = "m32r";
const char *bfem_mn10300_str = "mn10300";
const char *bfem_openrisc_str = "openrisc";
const char *bfem_blackfin_str = "blackfin";
const char *bfem_altera_nios2_str = "altera_nios2";
const char *bfem_ti_c6000_str = "ti_c6000";
const char *bfem_aarch64_str = "aarch64";
const char *bfem_frv_str = "frv";
const char *bfem_avr32_str = "avr32";
const char *bfem_alpha_str = "alpha";
const char *bfem_cygnus_v850_str = "cygnus_v850";
const char *bfem_cygnus_m32r_str = "cygnus_m32r";
const char *bfem_s390_old_str = "s390_old";
const char *bfem_cygnus_mn10300_str = "cygnus_mn10300";

const char *
e_machine_to_str(bfelf64_half value)
{
    switch (value)
    {
        case bfem_none: return bfem_none_str;
        case bfem_m32: return bfem_m32_str;
        case bfem_sparc: return bfem_sparc_str;
        case bfem_386: return bfem_386_str;
        case bfem_68k: return bfem_68k_str;
        case bfem_88k: return bfem_88k_str;
        case bfem_486: return bfem_486_str;
        case bfem_860: return bfem_860_str;
        case bfem_mips: return bfem_mips_str;
        case bfem_mips_rs3_le: return bfem_mips_rs3_le_str;
        case bfem_mips_rs4_be: return bfem_mips_rs4_be_str;
        case bfem_parisc: return bfem_parisc_str;
        case bfem_sparc32plus: return bfem_sparc32plus_str;
        case bfem_ppc: return bfem_ppc_str;
        case bfem_ppc64: return bfem_ppc64_str;
        case bfem_spu: return bfem_spu_str;
        case bfem_arm: return bfem_arm_str;
        case bfem_sh: return bfem_sh_str;
        case bfem_sparcv9: return bfem_sparcv9_str;
        case bfem_h8_300: return bfem_h8_300_str;
        case bfem_ia_64: return bfem_ia_64_str;
        case bfem_x86_64: return bfem_x86_64_str;
        case bfem_s390: return bfem_s390_str;
        case bfem_cris: return bfem_cris_str;
        case bfem_v850: return bfem_v850_str;
        case bfem_m32r: return bfem_m32r_str;
        case bfem_mn10300: return bfem_mn10300_str;
        case bfem_openrisc: return bfem_openrisc_str;
        case bfem_blackfin: return bfem_blackfin_str;
        case bfem_altera_nios2: return bfem_altera_nios2_str;
        case bfem_ti_c6000: return bfem_ti_c6000_str;
        case bfem_aarch64: return bfem_aarch64_str;
        case bfem_frv: return bfem_frv_str;
        case bfem_avr32: return bfem_avr32_str;
        case bfem_alpha: return bfem_alpha_str;
        case bfem_cygnus_v850: return bfem_cygnus_v850_str;
        case bfem_cygnus_m32r: return bfem_cygnus_m32r_str;
        case bfem_s390_old: return bfem_s390_old_str;
        case bfem_cygnus_mn10300: return bfem_cygnus_mn10300_str;
        default: return "Unknown e_machine";
    }
}

bfelf64_sword
bfelf_file_print_header(struct bfelf_file_t *ef)
{
    if (!ef)
        return BFELF_ERROR_INVALID_ARG;

    if (ef->valid != BFELF_TRUE)
        return BFELF_ERROR_INVALID_FILE;

    DEBUG("ELF Header:\n");
    DEBUG("  %-35s %X %c %c %c\n", "Magic:", ef->ehdr->e_ident[bfei_mag0]
          , ef->ehdr->e_ident[bfei_mag1]
          , ef->ehdr->e_ident[bfei_mag2]
          , ef->ehdr->e_ident[bfei_mag3]);

    DEBUG("  %-35s %s\n", "Class:", ei_class_to_str(ef->ehdr->e_ident[bfei_class]));
    DEBUG("  %-35s %s\n", "Data:", ei_data_to_str(ef->ehdr->e_ident[bfei_data]));
    DEBUG("  %-35s %s\n", "Version:", version_to_str(ef->ehdr->e_ident[bfei_version]));
    DEBUG("  %-35s %s\n", "OS/ABI:", ei_osabi_to_str(ef->ehdr->e_ident[bfei_osabi]));
    DEBUG("  %-35s %d\n", "ABI Version:", ef->ehdr->e_ident[bfei_abiversion]);
    DEBUG("  %-35s %s\n", "Type:", e_type_to_str(ef->ehdr->e_type));
    DEBUG("  %-35s %s\n", "Machine:", e_machine_to_str(ef->ehdr->e_machine));
    DEBUG("  %-35s %s\n", "Version:", version_to_str(ef->ehdr->e_version));
    DEBUG("  %-35s 0x%" PRIu64 "\n", "Entry point address:", ef->ehdr->e_entry);
    DEBUG("  %-35s 0x%" PRIu64 ", %" PRIu64 " (bytes into file)\n", "Start of program headers:", ef->ehdr->e_phoff, ef->ehdr->e_phoff);
    DEBUG("  %-35s 0x%" PRIu64 ", %" PRIu64 " (bytes into file)\n", "Start of section headers:", ef->ehdr->e_shoff, ef->ehdr->e_shoff);
    DEBUG("  %-35s 0x%X\n", "Flags:", ef->ehdr->e_flags);
    DEBUG("  %-35s %d (bytes)\n", "Size of this header:", ef->ehdr->e_ehsize);
    DEBUG("  %-35s %d (bytes)\n", "Size of program headers:", ef->ehdr->e_phentsize);
    DEBUG("  %-35s %d\n", "Num of program headers:", ef->ehdr->e_phnum);
    DEBUG("  %-35s %d (bytes)\n", "Size of section headers:", ef->ehdr->e_shentsize);
    DEBUG("  %-35s %d\n", "Num of section headers:", ef->ehdr->e_shnum);
    DEBUG("  %-35s %d\n", "Section header string table index:", ef->ehdr->e_shstrndx);

    DEBUG("\n");

    return BFELF_SUCCESS;
}

/******************************************************************************/
/* ELF Section Header Table                                                   */
/******************************************************************************/

const char *bfsht_null_str = "Unused (bfsht_null)";
const char *bfsht_progbits_str = "Program data (bfsht_progbits)";
const char *bfsht_symtab_str = "Symbol table (bfsht_symtab)";
const char *bfsht_strtab_str = "String table (bfsht_strtab)";
const char *bfsht_rela_str = "Rela (bfsht_rela)";
const char *bfsht_hash_str = "Hash table (bfsht_hash)";
const char *bfsht_dynamic_str = "Dynamic linking table (bfsht_dynamic)";
const char *bfsht_note_str = "Note info (bfsht_note)";
const char *bfsht_nobits_str = "Uninitialized (bfsht_nobits)";
const char *bfsht_rel_str = "Rel (bfsht_rel)";
const char *bfsht_shlib_str = "Reserved (bfsht_shlib)";
const char *bfsht_dynsym_str = "Dynamic loader table (bfsht_dynsym)";
const char *bfsht_loos_str = "Process specific (bfsht_loos)";
const char *bfsht_hios_str = "Process specific (bfsht_hios)";
const char *bfsht_loproc_str = "Process specific (bfsht_loproc)";
const char *bfsht_hiproc_str = "Process specific (bfsht_hiproc)";

const char *
sh_type_to_str(bfelf64_word value)
{
    switch (value)
    {
        case bfsht_null: return bfsht_null_str;
        case bfsht_progbits: return bfsht_progbits_str;
        case bfsht_symtab: return bfsht_symtab_str;
        case bfsht_strtab: return bfsht_strtab_str;
        case bfsht_rela: return bfsht_rela_str;
        case bfsht_hash: return bfsht_hash_str;
        case bfsht_dynamic: return bfsht_dynamic_str;
        case bfsht_note: return bfsht_note_str;
        case bfsht_nobits: return bfsht_nobits_str;
        case bfsht_rel: return bfsht_rel_str;
        case bfsht_shlib: return bfsht_shlib_str;
        case bfsht_dynsym: return bfsht_dynsym_str;
        case bfsht_loos: return bfsht_loos_str;
        case bfsht_hios: return bfsht_hios_str;
        case bfsht_loproc: return bfsht_loproc_str;
        case bfsht_hiproc: return bfsht_hiproc_str;
        default: return "Unknown sh_type";
    }
}

bfelf64_sword
sh_flags_is_writable(struct bfelf_shdr *shdr)
{
    if (!shdr)
        return BFELF_ERROR_INVALID_ARG;

    return (shdr->sh_flags & bfshf_write) != 0 ? BFELF_TRUE : BFELF_FALSE;
}

bfelf64_sword
sh_flags_is_allocated(struct bfelf_shdr *shdr)
{
    if (!shdr)
        return BFELF_ERROR_INVALID_ARG;

    return (shdr->sh_flags & bfshf_alloc) != 0 ? BFELF_TRUE : BFELF_FALSE;
}

bfelf64_sword
sh_flags_is_executable(struct bfelf_shdr *shdr)
{
    if (!shdr)
        return BFELF_ERROR_INVALID_ARG;

    return (shdr->sh_flags & bfshf_execinstr) != 0 ? BFELF_TRUE : BFELF_FALSE;
}

bfelf64_sword
bfelf_section_header(struct bfelf_file_t *ef,
                     bfelf64_word index,
                     struct bfelf_shdr **shdr)
{
    if (!ef || !ef->ehdr || !ef->shdrtab || !shdr)
        return BFELF_ERROR_INVALID_ARG;

    if (index >= ef->ehdr->e_shnum)
        return BFELF_ERROR_INVALID_INDEX;

    *shdr = &(ef->shdrtab[index]);

    return BFELF_SUCCESS;
}

bfelf64_sword
bfelf_print_section_header_table(struct bfelf_file_t *ef)
{
    bfelf64_word i = 0;
    bfelf64_sword ret = 0;

    if (!ef)
        return BFELF_ERROR_INVALID_ARG;

    if (ef->valid != BFELF_TRUE)
        return BFELF_ERROR_INVALID_FILE;

    for (i = 0; i < ef->ehdr->e_shnum; i++)
    {
        struct bfelf_shdr *shdr = 0;

        ret = bfelf_section_header(ef, i, &shdr);
        if (ret != BFELF_SUCCESS)
            return ret;

        ret = bfelf_print_section_header(ef, shdr);
        if (ret != BFELF_SUCCESS)
            return ret;
    }

    return BFELF_SUCCESS;
}

bfelf64_sword
bfelf_print_section_header(struct bfelf_file_t *ef,
                           struct bfelf_shdr *shdr)
{
    bfelf64_sword ret = 0;
    struct e_string_t section_name = {0};

    if (!ef || !shdr)
        return BFELF_ERROR_INVALID_ARG;

    if (ef->valid != BFELF_TRUE)
        return BFELF_ERROR_INVALID_FILE;

    ret = bfelf_section_name_string(ef, shdr, &section_name);
    if (ret != BFELF_SUCCESS)
        return ret;

    DEBUG("Section Header: %s\n", section_name.buf);
    DEBUG("  %-35s %s\n", "Type:", sh_type_to_str(shdr->sh_type));
    DEBUG("  %-35s ", "Flags:");

    if (sh_flags_is_writable(shdr) == BFELF_TRUE) { INFO("W "); }
    if (sh_flags_is_allocated(shdr) == BFELF_TRUE) { INFO("A "); }
    if (sh_flags_is_executable(shdr) == BFELF_TRUE) { INFO("E "); }

    INFO("\n");
    DEBUG("  %-35s 0x%" PRIu64 "\n", "Address:", shdr->sh_addr);
    DEBUG("  %-35s 0x%" PRIu64 "\n", "Offset:", shdr->sh_offset);
    DEBUG("  %-35s %" PRIu64 " (bytes)\n", "Size:", shdr->sh_size);
    DEBUG("  %-35s %u\n", "Linked Section:", shdr->sh_link);
    DEBUG("  %-35s %u\n", "Info:", shdr->sh_info);
    DEBUG("  %-35s %" PRIu64 "\n", "Address Alignment:", shdr->sh_addralign);
    DEBUG("  %-35s %" PRIu64 "\n", "Entry Size:", shdr->sh_entsize);

    DEBUG("\n");

    return BFELF_SUCCESS;
}

/******************************************************************************/
/* Section Name String Table                                                  */
/******************************************************************************/

bfelf64_sword
bfelf_string_table_entry(struct bfelf_file_t *ef,
                         struct bfelf_shdr *strtab,
                         bfelf64_word offset,
                         struct e_string_t *str)
{
    char *buf = 0;
    bfelf64_sword i = 0;
    bfelf64_sword max = 0;
    bfelf64_sword length = 0;

    if (!ef || !strtab || !str)
        return BFELF_ERROR_INVALID_ARG;

    if (ef->valid != BFELF_TRUE)
        return BFELF_ERROR_INVALID_FILE;

    if (offset > strtab->sh_size)
        return BFELF_ERROR_INVALID_OFFSET;

    buf = ef->file + strtab->sh_offset + offset;
    max = strtab->sh_size - offset;

    for (i = 0; i < max; i++, length++)
    {
        if (buf[i] == 0)
            break;
    }

    if (i == max)
        return BFELF_ERROR_INVALID_STRING_TABLE;

    str->buf = buf;
    str->len = length;

    return BFELF_SUCCESS;
}

bfelf64_sword
bfelf_section_name_string(struct bfelf_file_t *ef,
                          struct bfelf_shdr *shdr,
                          struct e_string_t *str)
{
    if (!ef || !shdr || !str)
        return BFELF_ERROR_INVALID_ARG;

    if (ef->valid != BFELF_TRUE)
        return BFELF_ERROR_INVALID_FILE;

    return bfelf_string_table_entry(ef, ef->shstrtab, shdr->sh_name, str);
}

/******************************************************************************/
/* ELF Dynamic Symbol Table                                                   */
/******************************************************************************/

const char *bfstb_local_str = "bfstb_local";
const char *bfstb_global_str = "bfstb_global";
const char *bfstb_weak_str = "bfstb_weak";
const char *bfstb_loos_str = "bfstb_loos";
const char *bfstb_hios_str = "bfstb_hios";
const char *bfstb_loproc_str = "bfstb_loproc";
const char *bfstb_hiproc_str = "bfstb_hiproc";

const char *
stb_to_str(bfelf64_word value)
{
    switch (BFELF_SYM_BIND(value))
    {
        case bfstb_local: return bfstb_local_str;
        case bfstb_global: return bfstb_global_str;
        case bfstb_weak: return bfstb_weak_str;
        case bfstb_loos: return bfstb_loos_str;
        case bfstb_hios: return bfstb_hios_str;
        case bfstb_loproc: return bfstb_loproc_str;
        case bfstb_hiproc: return bfstb_hiproc_str;
        default: return "Unknown st_info (bind)";
    }
}

const char *bfstt_notype_str = "bfstt_notype";
const char *bfstt_object_str = "bfstt_object";
const char *bfstt_func_str = "bfstt_func";
const char *bfstt_section_str = "bfstt_section";
const char *bfstt_file_str = "bfstt_file";
const char *bfstt_loos_str = "bfstt_loos";
const char *bfstt_hios_str = "bfstt_hios";
const char *bfstt_loproc_str = "bfstt_loproc";
const char *bfstt_hiproc_str = "bfstt_hiproc";

const char *
stt_to_str(bfelf64_word value)
{
    switch (BFELF_SYM_TYPE(value))
    {
        case bfstt_notype: return bfstt_notype_str;
        case bfstt_object: return bfstt_object_str;
        case bfstt_func: return bfstt_func_str;
        case bfstt_section: return bfstt_section_str;
        case bfstt_file: return bfstt_file_str;
        case bfstt_loos: return bfstt_loos_str;
        case bfstt_hios: return bfstt_hios_str;
        case bfstt_loproc: return bfstt_loproc_str;
        case bfstt_hiproc: return bfstt_hiproc_str;
        default: return "Unknown st_info (bind)";
    }
}

bfelf64_sword
bfelf_symbol_by_index(struct bfelf_file_t *ef,
                      bfelf64_word index,
                      struct bfelf_sym **sym)
{
    if (!ef || !sym)
        return BFELF_ERROR_INVALID_ARG;

    if (index >= ef->symnum)
        return BFELF_ERROR_INVALID_INDEX;

    if (ef->valid != BFELF_TRUE)
        return BFELF_ERROR_INVALID_FILE;

    *sym = &(ef->symtab[index]);

    return BFELF_SUCCESS;
}

bfelf64_sword
bfelf_symbol_by_name(struct bfelf_file_t *ef,
                     struct e_string_t *name,
                     struct bfelf_sym **sym)
{
    bfelf64_word i = 0;
    bfelf64_sword ret = 0;

    /* TODO: Use .hash instead of a O(n) loop. */

    if (!ef || !name || !sym)
        return BFELF_ERROR_INVALID_ARG;

    if (ef->valid != BFELF_TRUE)
        return BFELF_ERROR_INVALID_FILE;

    for (i = 0; i < ef->symnum; i++)
    {
        struct bfelf_sym *sym = 0;
        struct e_string_t str = {0};

        ret = bfelf_symbol_by_index(ef, i, &sym);
        if (ret != BFELF_SUCCESS)
            return ret;

        ret = bfelf_string_table_entry(ef, ef->strtab, sym->st_name, &str);
        if (ret != BFELF_SUCCESS)
            return ret;

        ret = bfelf_strcmp(name, &str);
        if (ret == BFELF_FALSE) continue;
        if (ret == BFELF_TRUE) break;
        return ret;
    }

    if (i != ef->symnum)
    {
        *sym = &(ef->symtab[i]);
        return BFELF_SUCCESS;
    }

    return BFELF_ERROR_NO_SUCH_SYMBOL;
}

bfelf64_sword
bfelf_symbol_by_name_global(struct bfelf_file_t *efl,
                            struct e_string_t *name,
                            struct bfelf_file_t **efr,
                            struct bfelf_sym **sym)
{
    bfelf64_word i = 0;
    bfelf64_sword ret = 0;
    struct bfelf_sym *tmpsym = 0;
    struct bfelf_file_t *tmpef = efl;

    if (!efl || !name || !efr || !sym)
        return BFELF_ERROR_INVALID_ARG;

    if (efl->valid != BFELF_TRUE)
        return BFELF_ERROR_INVALID_FILE;

    ret = bfelf_symbol_by_name(tmpef, name, &tmpsym);
    switch (ret)
    {
        case BFELF_SUCCESS:
            if (tmpsym->st_value != 0)
                goto found;

        case BFELF_ERROR_NO_SUCH_SYMBOL:
            break;

        default:
            return ret;
    };

    for (i = 0; i < efl->efnum; i++)
    {
        tmpef = efl->eftab[i];

        ret = bfelf_symbol_by_name(tmpef, name, &tmpsym);
        switch (ret)
        {
            case BFELF_SUCCESS:
                if (tmpsym->st_value != 0)
                    goto found;

                continue;

            case BFELF_ERROR_NO_SUCH_SYMBOL:
                break;

            default:
                return ret;
        };
    }

    ALERT("failed to find: %s\n", name->buf);

    return BFELF_ERROR_NO_SUCH_SYMBOL;

found:

    *efr = tmpef;
    *sym = tmpsym;

    return BFELF_SUCCESS;
}

bfelf64_sword
bfelf_resolve_symbol(struct bfelf_file_t *ef,
                     struct e_string_t *name,
                     void **addr)
{
    bfelf64_sword ret = 0;
    struct bfelf_sym *sym = 0;
    struct bfelf_file_t *efr = 0;

    if (!ef || !name || !addr)
        return BFELF_ERROR_INVALID_ARG;

    if (ef->valid != BFELF_TRUE)
        return BFELF_ERROR_INVALID_FILE;

    ret = bfelf_symbol_by_name_global(ef, name, &efr, &sym);
    if (ret != BFELF_SUCCESS)
        return ret;

    *addr = efr->exec + sym->st_value;

    return BFELF_SUCCESS;
}

bfelf64_sword
bfelf_print_sym_table(struct bfelf_file_t *ef)
{
    bfelf64_word i = 0;
    bfelf64_sword ret = 0;

    if (!ef)
        return BFELF_ERROR_INVALID_ARG;

    if (ef->valid != BFELF_TRUE)
        return BFELF_ERROR_INVALID_FILE;

    for (i = 0; i < ef->symnum; i++)
    {
        struct bfelf_sym *sym = 0;

        ret = bfelf_symbol_by_index(ef, i, &sym);
        if (ret != BFELF_SUCCESS)
            return ret;

        ret = bfelf_print_sym(ef, sym);
        if (ret != BFELF_SUCCESS)
            return ret;
    }

    DEBUG("\n");

    return BFELF_SUCCESS;
}

bfelf64_sword
bfelf_print_sym(struct bfelf_file_t *ef,
                struct bfelf_sym *sym)
{
    bfelf64_sword ret = 0;
    struct e_string_t str = {0};

    if (!ef || !sym)
        return BFELF_ERROR_INVALID_ARG;

    if (ef->valid != BFELF_TRUE)
        return BFELF_ERROR_INVALID_FILE;

    ret = bfelf_string_table_entry(ef, ef->strtab, sym->st_name, &str);
    if (ret != BFELF_SUCCESS)
        return ret;

#ifdef PRINT_DETAILED_SYM

    DEBUG("Symbol: %s\n", str.buf);
    DEBUG("  %-35s %s\n", "Bind:", stb_to_str(sym->st_info));
    DEBUG("  %-35s %s\n", "Type:", stt_to_str(sym->st_info));
    DEBUG("  %-35s %d\n", "Section Index:", sym->st_shndx);
    DEBUG("  %-35s 0x%" PRIu64 "\n", "Value:", sym->st_value);
    DEBUG("  %-35s 0x%" PRIu64 "\n", "Size:", sym->st_size);

    DEBUG("\n");

#else

    DEBUG("Symbol: %-29s 0x%08" PRIu64 " %-2s %-12s %s\n", str.buf, sym->st_value, " ",
          stb_to_str(sym->st_info),
          stt_to_str(sym->st_info));

#endif

    return BFELF_SUCCESS;
}

/******************************************************************************/
/* ELF Relocations                                                            */
/******************************************************************************/

const char *BFR_X86_64_64_STR = "BFR_X86_64_64";
const char *BFR_X86_64_GLOB_DAT_STR = "BFR_X86_64_GLOB_DAT";
const char *BFR_X86_64_JUMP_SLOT_STR = "BFR_X86_64_JUMP_SLOT";
const char *BFR_X86_64_RELATIVE_STR = "BFR_X86_64_RELATIVE";

const char *
rel_type_to_str(bfelf64_xword value)
{
    switch (BFELF_REL_TYPE(value))
    {
        case BFR_X86_64_64: return BFR_X86_64_64_STR;
        case BFR_X86_64_GLOB_DAT: return BFR_X86_64_GLOB_DAT_STR;
        case BFR_X86_64_JUMP_SLOT: return BFR_X86_64_JUMP_SLOT_STR;
        case BFR_X86_64_RELATIVE: return BFR_X86_64_RELATIVE_STR;
        default: return "Unknown BFELF_REL_TYPE(r_info)";
    }
}

bfelf64_sword
bfelf_relocate_symbol(struct bfelf_file_t *ef,
                      struct bfelf_rel *rel)
{
    bfelf64_addr *ptr = 0;
    bfelf64_sword ret = 0;
    struct bfelf_sym *sym = 0;
    struct e_string_t name = {0};
    struct bfelf_file_t *efr = 0;

    if (!ef || !rel)
        return BFELF_ERROR_INVALID_ARG;

    if (ef->valid != BFELF_TRUE)
        return BFELF_ERROR_INVALID_FILE;

    ret = bfelf_symbol_by_index(ef, BFELF_REL_SYM(rel->r_info), &sym);
    if (ret != BFELF_SUCCESS)
        return ret;

    ret = bfelf_string_table_entry(ef, ef->strtab, sym->st_name, &name);
    if (ret != BFELF_SUCCESS)
        return ret;

    ret = bfelf_symbol_by_name_global(ef, &name, &efr, &sym);
    if (ret != BFELF_SUCCESS)
        return ret;

    ptr = (bfelf64_addr *)(ef->exec + rel->r_offset);

    if (ptr > (bfelf64_addr *)(ef->exec + ef->esize))
        return BFELF_ERROR_INVALID_FILE;

    /* TODO: Remove the relocation for BFR_X86_64_JUMP_SLOT, and instead
       fill in the address of a function that does the relocation and
       then jumps to the value that should have been there. Called
       lazy loading */

    switch (BFELF_REL_TYPE(rel->r_info))
    {
        case BFR_X86_64_GLOB_DAT:
        case BFR_X86_64_JUMP_SLOT:
            *ptr = (bfelf64_addr)(efr->exec + sym->st_value);
            break;

        default:
            return BFELF_ERROR_INVALID_RELOCATION_TYPE;
    }

    return BFELF_SUCCESS;
}

bfelf64_sword
bfelf_relocate_symbol_addend(struct bfelf_file_t *ef,
                             struct bfelf_rela *rela)
{
    bfelf64_addr *ptr = 0;
    bfelf64_sword ret = 0;
    struct bfelf_sym *sym = 0;
    struct e_string_t name = {0};
    struct bfelf_file_t *efr = 0;

    if (!ef || !rela)
        return BFELF_ERROR_INVALID_ARG;

    if (ef->valid != BFELF_TRUE)
        return BFELF_ERROR_INVALID_FILE;

    ret = bfelf_symbol_by_index(ef, BFELF_REL_SYM(rela->r_info), &sym);
    if (ret != BFELF_SUCCESS)
        return ret;

    switch (BFELF_REL_TYPE(rela->r_info))
    {
        case BFR_X86_64_RELATIVE:
            break;

        default:
        {
            ret = bfelf_string_table_entry(ef, ef->strtab, sym->st_name, &name);
            if (ret != BFELF_SUCCESS)
                return ret;

            ret = bfelf_symbol_by_name_global(ef, &name, &efr, &sym);
            if (ret != BFELF_SUCCESS)
                return ret;
        }
    };

    ptr = (bfelf64_addr *)(ef->exec + rela->r_offset);

    if (ptr > (bfelf64_addr *)(ef->exec + ef->esize))
        return BFELF_ERROR_INVALID_FILE;

    /* TODO: Remove the relocation for BFR_X86_64_JUMP_SLOT, and instead
       fill in the address of a function that does the relocation and
       then jumps to the value that should have been there. Called
       lazy loading */

    switch (BFELF_REL_TYPE(rela->r_info))
    {
        case BFR_X86_64_64:
            *ptr = (bfelf64_addr)(efr->exec + sym->st_value + rela->r_addend);
            break;

        case BFR_X86_64_GLOB_DAT:
        case BFR_X86_64_JUMP_SLOT:
            *ptr = (bfelf64_addr)(efr->exec + sym->st_value);
            break;

        case BFR_X86_64_RELATIVE:
            *ptr = (bfelf64_addr)(ef->exec + rela->r_addend);
            break;

        default:
            return BFELF_ERROR_INVALID_RELOCATION_TYPE;
    }

    return BFELF_SUCCESS;
}

bfelf64_sword
bfelf_relocate_symbols(struct bfelf_file_t *ef)
{
    bfelf64_word t = 0;
    bfelf64_word r = 0;
    bfelf64_sword ret = 0;

    if (!ef)
        return BFELF_ERROR_INVALID_ARG;

    if (ef->valid != BFELF_TRUE)
        return BFELF_ERROR_INVALID_FILE;

    for (t = 0; t < ef->num_rel; t++)
    {
        for (r = 0; r < ef->bfreltab[t].num; r++)
        {
            ret = bfelf_relocate_symbol(ef, &(ef->bfreltab[t].tab[r]));
            if (ret != BFELF_SUCCESS)
                return ret;
        }
    }

    for (t = 0; t < ef->num_rela; t++)
    {
        for (r = 0; r < ef->bfrelatab[t].num; r++)
        {
            ret = bfelf_relocate_symbol_addend(ef, &(ef->bfrelatab[t].tab[r]));
            if (ret != BFELF_SUCCESS)
                return ret;
        }
    }

    return BFELF_SUCCESS;
}

bfelf64_sword
bfelf_print_relocation(struct bfelf_rel *rel)
{
    if (!rel)
        return BFELF_ERROR_INVALID_ARG;

#ifdef PRINT_DETAILED_REL

    DEBUG("Relocation:\n");
    DEBUG("  %-35s 0x%08" PRIu64 "\n", "Offset:", rel->r_offset);
    DEBUG("  %-35s %" PRId64 "\n", "Symbol:", BFELF_REL_SYM(rel->r_info));
    DEBUG("  %-35s %s\n", "Type:", rel_type_to_str(rel->r_info));

    DEBUG("\n");

#else

    DEBUG("Relocation: %-20s 0x%08" PRIu64 " %04" PRId64 "\n", rel_type_to_str(rel->r_info),
          rel->r_offset,
          BFELF_REL_SYM(rel->r_info));

#endif

    return BFELF_SUCCESS;
}

bfelf64_sword
bfelf_print_relocation_addend(struct bfelf_rela *rela)
{
    if (!rela)
        return BFELF_ERROR_INVALID_ARG;

#ifdef PRINT_DETAILED_REL

    DEBUG("Relocation:\n");
    DEBUG("  %-35s 0x%08" PRIu64 "\n", "Offset:", rela->r_offset);
    DEBUG("  %-35s %" PRId64 "\n", "Symbol:", BFELF_REL_SYM(rela->r_info));
    DEBUG("  %-35s %s\n", "Type:", rel_type_to_str(rela->r_info));
    DEBUG("  %-35s 0x%" PRIu64 "\n", "Addend:", rela->r_addend);

    DEBUG("\n");

#else

    DEBUG("Relocation: %-20s 0x%08" PRIu64 " %04" PRId64 " 0x%08" PRIu64 "\n", rel_type_to_str(rela->r_info),
          rela->r_offset,
          BFELF_REL_SYM(rela->r_info),
          rela->r_addend);

#endif

    return BFELF_SUCCESS;
}

bfelf64_sword
bfelf_print_relocations(struct bfelf_file_t *ef)
{
    bfelf64_word t = 0;
    bfelf64_word r = 0;
    bfelf64_sword ret = 0;

    if (!ef)
        return BFELF_ERROR_INVALID_ARG;

    if (ef->valid != BFELF_TRUE)
        return BFELF_ERROR_INVALID_FILE;

    for (t = 0; t < ef->num_rel; t++)
    {
        for (r = 0; r < ef->bfreltab[t].num; r++)
        {
            ret = bfelf_print_relocation(&(ef->bfreltab[t].tab[r]));
            if (ret != BFELF_SUCCESS)
                return ret;
        }
    }

    for (t = 0; t < ef->num_rela; t++)
    {
        for (r = 0; r < ef->bfrelatab[t].num; r++)
        {
            ret = bfelf_print_relocation_addend(&(ef->bfrelatab[t].tab[r]));
            if (ret != BFELF_SUCCESS)
                return ret;
        }
    }

    DEBUG("\n");

    return BFELF_SUCCESS;
}

/******************************************************************************/
/* ELF CTORS / DTORS                                                          */
/******************************************************************************/

bfelf64_sword
bfelf_ctor_num(struct bfelf_file_t *ef)
{
    if (!ef)
        return BFELF_ERROR_INVALID_ARG;

    if (ef->valid != BFELF_TRUE)
        return BFELF_ERROR_INVALID_FILE;

    if (ef->ctors == 0)
        return 0;

    return ef->ctors->sh_size / sizeof(void *);
}

bfelf64_sword
bfelf_dtor_num(struct bfelf_file_t *ef)
{
    if (!ef)
        return BFELF_ERROR_INVALID_ARG;

    if (ef->valid != BFELF_TRUE)
        return BFELF_ERROR_INVALID_FILE;

    if (ef->dtors == 0)
        return 0;

    return ef->dtors->sh_size / sizeof(void *);
}

bfelf64_sword
bfelf_resolve_ctor(struct bfelf_file_t *ef,
                   bfelf64_word index,
                   void **addr)
{
    bfelf64_word num = 0;
    bfelf64_addr sym = 0;

    if (!ef || !addr)
        return BFELF_ERROR_INVALID_ARG;

    if (ef->valid != BFELF_TRUE)
        return BFELF_ERROR_INVALID_FILE;

    num = bfelf_ctor_num(ef);
    if (index >= num)
        return BFELF_ERROR_INVALID_INDEX;

    sym = ((bfelf64_addr *)(ef->file + ef->ctors->sh_offset))[index];
    *addr = ef->exec + sym;

    return BFELF_SUCCESS;
}

bfelf64_sword
bfelf_resolve_dtor(struct bfelf_file_t *ef,
                   bfelf64_word index,
                   void **addr)
{
    bfelf64_word num = 0;
    bfelf64_addr sym = 0;

    if (!ef || !addr)
        return BFELF_ERROR_INVALID_ARG;

    if (ef->valid != BFELF_TRUE)
        return BFELF_ERROR_INVALID_FILE;

    num = bfelf_dtor_num(ef);
    if (index >= num)
        return BFELF_ERROR_INVALID_INDEX;

    sym = ((bfelf64_addr *)(ef->file + ef->dtors->sh_offset))[index];
    *addr = ef->exec + sym;

    return BFELF_SUCCESS;
}

/******************************************************************************/
/* ELF INIT / FINI                                                            */
/******************************************************************************/

bfelf64_sword
bfelf_init_num(struct bfelf_file_t *ef)
{
    if (!ef)
        return BFELF_ERROR_INVALID_ARG;

    if (ef->valid != BFELF_TRUE)
        return BFELF_ERROR_INVALID_FILE;

    if (ef->init_array == 0)
        return 0;

    return ef->init_array->sh_size / sizeof(void *);
}

bfelf64_sword
bfelf_fini_num(struct bfelf_file_t *ef)
{
    if (!ef)
        return BFELF_ERROR_INVALID_ARG;

    if (ef->valid != BFELF_TRUE)
        return BFELF_ERROR_INVALID_FILE;

    if (ef->fini_array == 0)
        return 0;

    return ef->fini_array->sh_size / sizeof(void *);
}

bfelf64_sword
bfelf_resolve_init(struct bfelf_file_t *ef,
                   bfelf64_word index,
                   void **addr)
{
    bfelf64_word num = 0;
    bfelf64_addr sym = 0;

    if (!ef || !addr)
        return BFELF_ERROR_INVALID_ARG;

    if (ef->valid != BFELF_TRUE)
        return BFELF_ERROR_INVALID_FILE;

    num = bfelf_init_num(ef);
    if (index >= num)
        return BFELF_ERROR_INVALID_INDEX;

    sym = ((bfelf64_addr *)(ef->file + ef->init_array->sh_offset))[index];
    *addr = ef->exec + sym;

    return BFELF_SUCCESS;
}

bfelf64_sword
bfelf_resolve_fini(struct bfelf_file_t *ef,
                   bfelf64_word index,
                   void **addr)
{
    bfelf64_word num = 0;
    bfelf64_addr sym = 0;

    if (!ef || !addr)
        return BFELF_ERROR_INVALID_ARG;

    if (ef->valid != BFELF_TRUE)
        return BFELF_ERROR_INVALID_FILE;

    num = bfelf_fini_num(ef);
    if (index >= num)
        return BFELF_ERROR_INVALID_INDEX;

    sym = ((bfelf64_addr *)(ef->file + ef->fini_array->sh_offset))[index];
    *addr = ef->exec + sym;

    return BFELF_SUCCESS;
}

/******************************************************************************/
/* ELF Program Header                                                         */
/******************************************************************************/

/* TODO: Need function to return a map that explains how to set the permissions
   of the memory used to load the ELF file. This way, portions of the RAM that
   holds the program can be RW and other portions can be RE */

const char *bfpt_null_str = "Unused entry (bfpt_null)";
const char *bfpt_load_str = "Loadable segment (bfpt_load)";
const char *bfpt_dynamic_str = "Dynamic linking tables (bfpt_dynamic)";
const char *bfpt_interp_str = "Program interpreter path name (bfpt_interp)";
const char *bfpt_note_str = "Note sections (bfpt_note)";
const char *bfpt_shlib_str = "Reserved (bfpt_shlib)";
const char *bfpt_phdr_str = "Program header table (bfpt_phdr)";
const char *bfpt_loos_str = "Environment specific (bfpt_loos)";
const char *bfpt_hios_str = "Environment specific (bfpt_hios)";
const char *bfpt_loproc_str = "Processor specific (bfpt_loproc)";
const char *bfpt_hiproc_str = "Processor specific (bfpt_hiproc)";

const char *
p_type_to_str(bfelf64_word value)
{
    switch (value)
    {
        case bfpt_null: return bfpt_null_str;
        case bfpt_load: return bfpt_load_str;
        case bfpt_dynamic: return bfpt_dynamic_str;
        case bfpt_interp: return bfpt_interp_str;
        case bfpt_note: return bfpt_note_str;
        case bfpt_shlib: return bfpt_shlib_str;
        case bfpt_phdr: return bfpt_phdr_str;
        case bfpt_loos: return bfpt_loos_str;
        case bfpt_hios: return bfpt_hios_str;
        case bfpt_loproc: return bfpt_loproc_str;
        case bfpt_hiproc: return bfpt_hiproc_str;
        default: return "Unknown p_type";
    }
}

bfelf64_sword
p_flags_is_executable(struct bfelf_phdr *phdr)
{
    if (!phdr)
        return BFELF_ERROR_INVALID_ARG;

    return (phdr->p_flags & bfpf_x) != 0 ? BFELF_TRUE : BFELF_FALSE;
}

bfelf64_sword
p_flags_is_writable(struct bfelf_phdr *phdr)
{
    if (!phdr)
        return BFELF_ERROR_INVALID_ARG;

    return (phdr->p_flags & bfpf_w) != 0 ? BFELF_TRUE : BFELF_FALSE;
}

bfelf64_sword
p_flags_is_readable(struct bfelf_phdr *phdr)
{
    if (!phdr)
        return BFELF_ERROR_INVALID_ARG;

    return (phdr->p_flags & bfpf_r) != 0 ? BFELF_TRUE : BFELF_FALSE;
}

bfelf64_sword
bfelf_program_header(struct bfelf_file_t *ef,
                     bfelf64_word index,
                     struct bfelf_phdr **phdr)
{
    if (!ef || !ef->ehdr || !ef->phdrtab || !phdr)
        return BFELF_ERROR_INVALID_ARG;

    if (index >= ef->ehdr->e_phnum)
        return BFELF_ERROR_INVALID_INDEX;

    *phdr = &(ef->phdrtab[index]);

    return BFELF_SUCCESS;
}

bfelf64_sxword
bfelf_total_exec_size(struct bfelf_file_t *ef)
{
    bfelf64_word i = 0;
    bfelf64_sword ret = 0;
    bfelf64_sxword total_size = 0;

    if (!ef)
        return BFELF_ERROR_INVALID_ARG;

    if (ef->valid != BFELF_TRUE)
        return BFELF_ERROR_INVALID_FILE;

    for (i = 0; i < ef->ehdr->e_phnum; i++)
    {
        bfelf64_sxword size = 0;
        struct bfelf_phdr *phdr = 0;

        ret = bfelf_program_header(ef, i, &phdr);
        if (ret != BFELF_SUCCESS)
            return ret;

        size = phdr->p_vaddr + phdr->p_memsz;

        if (size > total_size)
            total_size = size;
    }

    return total_size;
}

bfelf64_sword
bfelf_load_segments(struct bfelf_file_t *ef)
{
    bfelf64_word i = 0;
    bfelf64_sword ret = 0;

    if (!ef)
        return BFELF_ERROR_INVALID_ARG;

    if (ef->valid != BFELF_TRUE)
        return BFELF_ERROR_INVALID_FILE;

    for (i = 0; i < ef->ehdr->e_phnum; i++)
    {
        struct bfelf_phdr *phdr = 0;

        ret = bfelf_program_header(ef, i, &phdr);
        if (ret != BFELF_SUCCESS)
            return ret;

        ret = bfelf_load_segment(ef, phdr);
        if (ret != BFELF_SUCCESS)
            return ret;
    }

    return BFELF_SUCCESS;
}

bfelf64_sword
bfelf_load_segment(struct bfelf_file_t *ef,
                   struct bfelf_phdr *phdr)
{
    char *exec = 0;
    char *file = 0;
    bfelf64_word i = 0;

    if (!ef || !phdr)
        return BFELF_ERROR_INVALID_ARG;

    if (ef->valid != BFELF_TRUE)
        return BFELF_ERROR_INVALID_FILE;

    if (phdr->p_vaddr + phdr->p_memsz > ef->esize)
        return BFELF_ERROR_INVALID_PH_MEMSZ;

    exec = ef->exec + phdr->p_vaddr;
    file = ef->file + phdr->p_offset;

    for (i = 0; i < phdr->p_filesz; i++)
        exec[i] = file[i];

    return BFELF_SUCCESS;
}

bfelf64_sword
bfelf_print_program_header_table(struct bfelf_file_t *ef)
{
    bfelf64_word i = 0;
    bfelf64_sword ret = 0;

    if (!ef)
        return BFELF_ERROR_INVALID_ARG;

    if (ef->valid != BFELF_TRUE)
        return BFELF_ERROR_INVALID_FILE;

    for (i = 0; i < ef->ehdr->e_phnum; i++)
    {
        struct bfelf_phdr *phdr = 0;

        ret = bfelf_program_header(ef, i, &phdr);
        if (ret != BFELF_SUCCESS)
            return ret;

        ret = bfelf_print_program_header(ef, phdr);
        if (ret != BFELF_SUCCESS)
            return ret;
    }

    return BFELF_SUCCESS;
}

bfelf64_sword
bfelf_print_program_header(struct bfelf_file_t *ef,
                           struct bfelf_phdr *phdr)
{
    if (!ef || !phdr)
        return BFELF_ERROR_INVALID_ARG;

    if (ef->valid != BFELF_TRUE)
        return BFELF_ERROR_INVALID_FILE;

    DEBUG("Program Header:\n");
    DEBUG("  %-35s %s\n", "Type:", p_type_to_str(phdr->p_type));
    DEBUG("  %-35s ", "Flags:");

    if (p_flags_is_executable(phdr) == BFELF_TRUE) { INFO("E "); }
    if (p_flags_is_writable(phdr) == BFELF_TRUE) { INFO("W "); }
    if (p_flags_is_readable(phdr) == BFELF_TRUE) { INFO("R "); }

    INFO("\n");
    DEBUG("  %-35s 0x%" PRIu64 "\n", "Offset:", phdr->p_offset);
    DEBUG("  %-35s 0x%" PRIu64 "\n", "Virtual Address:", phdr->p_vaddr);
    DEBUG("  %-35s 0x%" PRIu64 "\n", "Physical Address:", phdr->p_paddr);
    DEBUG("  %-35s %" PRIu64 " (bytes)\n", "File Size:", phdr->p_filesz);
    DEBUG("  %-35s %" PRIu64 " (bytes)\n", "Exec Size:", phdr->p_memsz);
    DEBUG("  %-35s 0x%" PRIu64 "\n", "Alignment:", phdr->p_align);

    DEBUG("\n");

    return BFELF_SUCCESS;
}
