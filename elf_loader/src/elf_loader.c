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

#include <elf_loader.h>

#ifdef ENABLE_ELF_DEBUGGING
#ifndef ELF_PRINTF
#include <stdio.h>
#define ELF_PRINTF printf
#endif
#define DEBUG(...) ELF_PRINTF("[ELF DEBUG]: " __VA_ARGS__)
#define INFO(...) ELF_PRINTF(__VA_ARGS__)
#else
#define DEBUG(...)
#define INFO(...)
#endif

/******************************************************************************/
/* ELF Helpers                                                                */
/******************************************************************************/

elf64_sword
elf_strcmp(struct e_string *str1, struct e_string *str2)
{
    elf64_sword i = 0;

    if (!str1 || !str2)
        return ELF_ERROR_INVALID_ARG;

    if (str1->len != str2->len)
        return ELF_FALSE;

    for (i = 0; i < str1->len && i < str2->len; i++)
    {
        if (str1->buf[i] != str2->buf[i])
            return ELF_FALSE;

        if (str1->buf[i] == 0 ||
            str2->buf[i] == 0)
        {
            return ELF_ERROR_INVALID_STRING;
        }
    }

    return ELF_TRUE;
}

/******************************************************************************/
/* ELF Error Codes                                                            */
/******************************************************************************/

const char *
elf_error(elf64_sword value)
{
    switch (value)
    {
        case ELF_SUCCESS: return ELF_SUCCESS_STR;
        case ELF_ERROR_INVALID_ARG: return ELF_ERROR_INVALID_ARG_STR;
        case ELF_ERROR_INVALID_FILE: return ELF_ERROR_INVALID_FILE_STR;
        case ELF_ERROR_INVALID_INDEX: return ELF_ERROR_INVALID_INDEX_STR;
        case ELF_ERROR_INVALID_OFFSET: return ELF_ERROR_INVALID_OFFSET_STR;
        case ELF_ERROR_INVALID_STRING: return ELF_ERROR_INVALID_STRING_STR;
        case ELF_ERROR_INVALID_EI_MAG0: return ELF_ERROR_INVALID_EI_MAG0_STR;
        case ELF_ERROR_INVALID_EI_MAG1: return ELF_ERROR_INVALID_EI_MAG1_STR;
        case ELF_ERROR_INVALID_EI_MAG2: return ELF_ERROR_INVALID_EI_MAG2_STR;
        case ELF_ERROR_INVALID_EI_MAG3: return ELF_ERROR_INVALID_EI_MAG3_STR;
        case ELF_ERROR_INVALID_EI_CLASS: return ELF_ERROR_INVALID_EI_CLASS_STR;
        case ELF_ERROR_INVALID_EI_DATA: return ELF_ERROR_INVALID_EI_DATA_STR;
        case ELF_ERROR_INVALID_EI_VERSION: return ELF_ERROR_INVALID_EI_VERSION_STR;
        case ELF_ERROR_INVALID_EI_OSABI: return ELF_ERROR_INVALID_EI_OSABI_STR;
        case ELF_ERROR_INVALID_EI_ABIVERSION: return ELF_ERROR_INVALID_EI_ABIVERSION_STR;
        case ELF_ERROR_INVALID_E_TYPE: return ELF_ERROR_INVALID_E_TYPE_STR;
        case ELF_ERROR_INVALID_E_MACHINE: return ELF_ERROR_INVALID_E_MACHINE_STR;
        case ELF_ERROR_INVALID_E_ENTRY: return ELF_ERROR_INVALID_E_ENTRY_STR;
        case ELF_ERROR_INVALID_E_PHOFF: return ELF_ERROR_INVALID_E_PHOFF_STR;
        case ELF_ERROR_INVALID_E_SHOFF: return ELF_ERROR_INVALID_E_SHOFF_STR;
        case ELF_ERROR_INVALID_E_FLAGS: return ELF_ERROR_INVALID_E_FLAGS_STR;
        case ELF_ERROR_INVALID_E_EHSIZE: return ELF_ERROR_INVALID_E_EHSIZE_STR;
        case ELF_ERROR_INVALID_E_PHENTSIZE: return ELF_ERROR_INVALID_E_PHENTSIZE_STR;
        case ELF_ERROR_INVALID_E_PHNUM: return ELF_ERROR_INVALID_E_PHNUM_STR;
        case ELF_ERROR_INVALID_E_SHENTSIZE: return ELF_ERROR_INVALID_E_SHENTSIZE_STR;
        case ELF_ERROR_INVALID_E_SHNUM: return ELF_ERROR_INVALID_E_SHNUM_STR;
        case ELF_ERROR_INVALID_E_SHSTRNDX: return ELF_ERROR_INVALID_E_SHSTRNDX_STR;
        case ELF_ERROR_INVALID_PHT: return ELF_ERROR_INVALID_PHT_STR;
        case ELF_ERROR_INVALID_SHT: return ELF_ERROR_INVALID_SHT_STR;
        case ELF_ERROR_INVALID_SH_NAME: return ELF_ERROR_INVALID_SH_NAME_STR;
        case ELF_ERROR_INVALID_SH_TYPE: return ELF_ERROR_INVALID_SH_TYPE_STR;
        case ELF_ERROR_INVALID_SH_FLAGS: return ELF_ERROR_INVALID_SH_FLAGS_STR;
        case ELF_ERROR_INVALID_SH_ADDR: return ELF_ERROR_INVALID_SH_ADDR_STR;
        case ELF_ERROR_INVALID_SH_OFFSET: return ELF_ERROR_INVALID_SH_OFFSET_STR;
        case ELF_ERROR_INVALID_SH_SIZE: return ELF_ERROR_INVALID_SH_SIZE_STR;
        case ELF_ERROR_INVALID_SH_LINK: return ELF_ERROR_INVALID_SH_LINK_STR;
        case ELF_ERROR_INVALID_SH_INFO: return ELF_ERROR_INVALID_SH_INFO_STR;
        case ELF_ERROR_INVALID_SH_ADDRALIGN: return ELF_ERROR_INVALID_SH_ADDRALIGN_STR;
        case ELF_ERROR_INVALID_SH_ENTSIZE: return ELF_ERROR_INVALID_SH_ENTSIZE_STR;
        case ELF_ERROR_INVALID_PH_TYPE: return ELF_ERROR_INVALID_PH_TYPE_STR;
        case ELF_ERROR_INVALID_PH_FLAGS: return ELF_ERROR_INVALID_PH_FLAGS_STR;
        case ELF_ERROR_INVALID_PH_OFFSET: return ELF_ERROR_INVALID_PH_OFFSET_STR;
        case ELF_ERROR_INVALID_PH_VADDR: return ELF_ERROR_INVALID_PH_VADDR_STR;
        case ELF_ERROR_INVALID_PH_PADDR: return ELF_ERROR_INVALID_PH_PADDR_STR;
        case ELF_ERROR_INVALID_PH_FILESZ: return ELF_ERROR_INVALID_PH_FILESZ_STR;
        case ELF_ERROR_INVALID_PH_MEMSZ: return ELF_ERROR_INVALID_PH_MEMSZ_STR;
        case ELF_ERROR_INVALID_PH_ALIGN: return ELF_ERROR_INVALID_PH_ALIGN_STR;
        case ELF_ERROR_INVALID_STRING_TABLE: return ELF_ERROR_INVALID_STRING_TABLE_STR;
        case ELF_ERROR_NO_SUCH_SYMBOL: return ELF_ERROR_NO_SUCH_SYMBOL_STR;
        case ELF_ERROR_SYMBOL_UNDEFINED: return ELF_ERROR_SYMBOL_UNDEFINED_STR;
        case ELF_ERROR_LOADER_FULL: return ELF_ERROR_LOADER_FULL_STR;
        case ELF_ERROR_INVALID_LOADER: return ELF_ERROR_INVALID_LOADER_STR;
        default: return "Undefined";
    }
}

/******************************************************************************/
/* ELF File                                                                   */
/******************************************************************************/

elf64_sword
elf_file_init(char *file, elf64_sword fsize, struct elf_file_t *ef)
{
    elf64_word i = 0;
    elf64_sword ret = 0;
    struct elf_shdr *dynsym = 0;
    struct elf_shdr *strtab = 0;
    struct elf_shdr *shstrtab = 0;

    if (!file || !ef)
        return ELF_ERROR_INVALID_ARG;

    for (i = 0; i < sizeof(struct elf_file_t); i++)
        ((char *)ef)[i] = 0;

    if (fsize < sizeof(struct elf64_ehdr))
        return ELF_ERROR_INVALID_ARG;

    ef->ehdr = (struct elf64_ehdr *)file;

    if (ef->ehdr->e_ident[ei_mag0] != 0x7F)
        return ELF_ERROR_INVALID_EI_MAG0;

    if (ef->ehdr->e_ident[ei_mag1] != 'E')
        return ELF_ERROR_INVALID_EI_MAG1;

    if (ef->ehdr->e_ident[ei_mag2] != 'L')
        return ELF_ERROR_INVALID_EI_MAG2;

    if (ef->ehdr->e_ident[ei_mag3] != 'F')
        return ELF_ERROR_INVALID_EI_MAG3;

    if (ef->ehdr->e_ident[ei_class] != elfclass64)
        return ELF_ERROR_INVALID_EI_CLASS;

    if (ef->ehdr->e_ident[ei_data] != elfdata2lsb)
        return ELF_ERROR_INVALID_EI_DATA;

    if (ef->ehdr->e_ident[ei_version] != ev_current)
        return ELF_ERROR_INVALID_EI_VERSION;

    if (ef->ehdr->e_ident[ei_osabi] != elfosabi_sysv)
        return ELF_ERROR_INVALID_EI_OSABI;

    if (ef->ehdr->e_ident[ei_abiversion] != 0)
        return ELF_ERROR_INVALID_EI_ABIVERSION;

    if (ef->ehdr->e_type != et_dyn)
        return ELF_ERROR_INVALID_E_TYPE;

    if (ef->ehdr->e_machine != em_x86_64)
        return ELF_ERROR_INVALID_E_MACHINE;

    if (ef->ehdr->e_version != ev_current)
        return ELF_ERROR_INVALID_EI_VERSION;

    if (ef->ehdr->e_entry <= 0 ||
        ef->ehdr->e_entry >= fsize)
    {
        return ELF_ERROR_INVALID_E_ENTRY;
    }

    if (ef->ehdr->e_phoff <= 0 ||
        ef->ehdr->e_phoff >= fsize)
    {
        return ELF_ERROR_INVALID_E_PHOFF;
    }

    if (ef->ehdr->e_shoff <= 0 ||
        ef->ehdr->e_shoff >= fsize)
    {
        return ELF_ERROR_INVALID_E_SHOFF;
    }

    if (ef->ehdr->e_flags != 0)
        return ELF_ERROR_INVALID_E_FLAGS;

    if (ef->ehdr->e_ehsize != sizeof(struct elf64_ehdr))
        return ELF_ERROR_INVALID_E_EHSIZE;

    if (ef->ehdr->e_phentsize != sizeof(struct elf_phdr))
        return ELF_ERROR_INVALID_E_PHENTSIZE;

    if (ef->ehdr->e_shentsize != sizeof(struct elf_shdr))
        return ELF_ERROR_INVALID_E_SHENTSIZE;

    if (ef->ehdr->e_shstrndx >= ef->ehdr->e_shnum)
        return ELF_ERROR_INVALID_E_SHSTRNDX;

    if (ef->ehdr->e_shoff + (ef->ehdr->e_shentsize * ef->ehdr->e_shnum) > fsize)
        return ELF_ERROR_INVALID_SHT;

    if (ef->ehdr->e_phoff + (ef->ehdr->e_phentsize * ef->ehdr->e_phnum) > fsize)
        return ELF_ERROR_INVALID_PHT;

    ef->file = file;
    ef->fsize = fsize;
    ef->shdrtab = (struct elf_shdr *)(file + ef->ehdr->e_shoff);
    ef->phdrtab = (struct elf_phdr *)(file + ef->ehdr->e_phoff);

    for (i = 0; i < ef->ehdr->e_shnum; i++)
    {
        struct elf_shdr *shdr;

        ret = elf_section_header(ef, i, &shdr);
        if (ret != ELF_SUCCESS)
            return ret;

        if (shdr->sh_offset + shdr->sh_size > ef->fsize)
            return ELF_ERROR_INVALID_SH_SIZE;
    }

    for (i = 0; i < ef->ehdr->e_phnum; i++)
    {
        struct elf_phdr *phdr;

        ret = elf_program_header(ef, i, &phdr);
        if (ret != ELF_SUCCESS)
            return ret;

        if (phdr->p_offset + phdr->p_filesz > ef->fsize)
            return ELF_ERROR_INVALID_PH_FILESZ;

        if (phdr->p_filesz > phdr->p_memsz)
            return ELF_ERROR_INVALID_PH_FILESZ;
    }

    for (i = 0; i < ef->ehdr->e_shnum; i++)
    {
        struct elf_shdr *shdr;

        ret = elf_section_header(ef, i, &shdr);
        if (ret != ELF_SUCCESS)
            return ret;

        if (shdr->sh_type == sht_dynsym)
        {
            dynsym = shdr;
            break;
        }
    }

    if (dynsym == 0)
        return ELF_ERROR_INVALID_FILE;

    ret = elf_section_header(ef, dynsym->sh_link, &strtab);
    if (ret != ELF_SUCCESS)
        return ret;

    if (strtab->sh_type != sht_strtab)
        return ELF_ERROR_INVALID_SH_TYPE;

    ret = elf_section_header(ef, ef->ehdr->e_shstrndx, &shstrtab);
    if (ret != ELF_SUCCESS)
        return ret;

    if (shstrtab->sh_type != sht_strtab)
        return ELF_ERROR_INVALID_SH_TYPE;

    ef->dynsym = dynsym;
    ef->strtab = strtab;
    ef->shstrtab = shstrtab;

    ef->symnum = dynsym->sh_size / sizeof(struct elf_sym);
    ef->symtab = (struct elf_sym *)(file + dynsym->sh_offset);

    for (i = 0; i < ef->ehdr->e_shnum; i++)
    {
        struct elf_shdr *shdr;

        ret = elf_section_header(ef, i, &shdr);
        if (ret != ELF_SUCCESS)
            return ret;

        if (shdr->sh_type == sht_rel)
        {
            ef->reltab[ef->num_rel].num = shdr->sh_size / sizeof(struct elf_rel);
            ef->reltab[ef->num_rel].tab = (struct elf_rel *)(ef->file + shdr->sh_offset);
            ef->num_rel++;
        }

        if (shdr->sh_type == sht_rela)
        {
            ef->relatab[ef->num_rela].num = shdr->sh_size / sizeof(struct elf_rela);
            ef->relatab[ef->num_rela].tab = (struct elf_rela *)(ef->file + shdr->sh_offset);
            ef->num_rela++;
        }
    }

    ef->valid = ELF_TRUE;

    return ELF_SUCCESS;
}

elf64_sword
elf_file_load(struct elf_file_t *ef, char *exec, elf64_sword esize)
{
    elf64_word i = 0;
    elf64_sword ret = 0;
    elf64_sxword total_size = 0;

    if (!ef || !exec)
        return ELF_ERROR_INVALID_ARG;

    if (esize < ef->fsize)
        return ELF_ERROR_INVALID_ARG;

    if (ef->valid != ELF_TRUE)
        return ELF_ERROR_INVALID_FILE;

    total_size = elf_total_exec_size(ef);
    if (total_size < ELF_SUCCESS)
        return ret;

    if (esize != total_size)
        return ELF_ERROR_INVALID_ARG;

    for (i = 0; i < esize; i++)
        exec[i] = 0;

    ef->exec = exec;
    ef->esize = esize;

    ret = elf_load_segments(ef);
    if (ret != ELF_SUCCESS)
        return ret;

    /* TODO: Make sure there are no duplicate symbols */

    return ELF_SUCCESS;
}

/******************************************************************************/
/* ELF Loader                                                                 */
/******************************************************************************/

elf64_sword
elf_loader_init(struct elf_loader_t *loader)
{
    elf64_word i = 0;

    if (!loader)
        return ELF_ERROR_INVALID_ARG;

    for (i = 0; i < sizeof(struct elf_loader_t); i++)
        ((char *)loader)[i] = 0;

    return ELF_SUCCESS;
}

elf64_sword
elf_loader_add(struct elf_loader_t *loader, struct elf_file_t *ef)
{
    if (!loader || !ef)
        return ELF_ERROR_INVALID_ARG;

    if (loader->num >= ELF_MAX_MODULES)
        return ELF_ERROR_LOADER_FULL;

    if (ef->valid != ELF_TRUE)
        return ELF_ERROR_INVALID_FILE;

    loader->efs[loader->num++] = ef;

    return ELF_SUCCESS;
}

elf64_sword
elf_loader_relocate(struct elf_loader_t *loader)
{
    elf64_word i = 0;
    elf64_word j = 0;
    elf64_sword ret = 0;

    if (!loader)
        return ELF_ERROR_INVALID_ARG;

    if (loader->num > ELF_MAX_MODULES)
        return ELF_ERROR_INVALID_LOADER;

    for (i = 0; i < loader->num; i++)
    {
        struct elf_file_t *ef1 = loader->efs[i];

        for (j = 0; j < ELF_MAX_MODULES; j++)
            ef1->eftab[j] = 0;

        for (j = 0; j < loader->num; j++)
        {
            struct elf_file_t *ef2 = loader->efs[j];

            if (ef1 == ef2)
                continue;

            ef1->eftab[ef1->efnum++] = ef2;
        }

        ret = elf_relocate_symbols(ef1);
        if (ret != ELF_SUCCESS)
            return ret;
    }

    return ELF_SUCCESS;
}

/******************************************************************************/
/* ELF File Header                                                            */
/******************************************************************************/

const char *
ei_class_to_str(unsigned char value)
{
    switch (value)
    {
        case elfclass32: return elfclass32_str;
        case elfclass64: return elfclass64_str;
        default: return "Unknown ei_class";
    }
}

const char *
ei_data_to_str(unsigned char value)
{
    switch (value)
    {
        case elfdata2lsb: return elfdata2lsb_str;
        case elfdata2msb: return elfdata2msb_str;
        default: return "Unknown ei_data";
    }
}

const char *
version_to_str(unsigned char value)
{
    switch (value)
    {
        case ev_current: return ev_current_str;
        default: return "Unknown version";
    }
}

const char *
ei_osabi_to_str(unsigned char value)
{
    switch (value)
    {
        case elfosabi_sysv: return elfosabi_sysv_str;
        case elfosabi_hpux: return elfosabi_hpux_str;
        case elfosabi_standalone: return elfosabi_standalone_str;
        default: return "Unknown ei_osabi";
    }
}

const char *
e_type_to_str(elf64_half value)
{
    switch (value)
    {
        case et_none: return et_none_str;
        case et_rel: return et_rel_str;
        case et_exec: return et_exec_str;
        case et_dyn: return et_dyn_str;
        case et_core: return et_core_str;
        case et_loos: return et_loos_str;
        case et_hios: return et_hios_str;
        case et_loproc: return et_loproc_str;
        case et_hiproc: return et_hiproc_str;
        default: return "Unknown e_type";
    }
}

const char *
e_machine_to_str(elf64_half value)
{
    switch (value)
    {
        case em_none: return em_none_str;
        case em_m32: return em_m32_str;
        case em_sparc: return em_sparc_str;
        case em_386: return em_386_str;
        case em_68k: return em_68k_str;
        case em_88k: return em_88k_str;
        case em_486: return em_486_str;
        case em_860: return em_860_str;
        case em_mips: return em_mips_str;
        case em_mips_rs3_le: return em_mips_rs3_le_str;
        case em_mips_rs4_be: return em_mips_rs4_be_str;
        case em_parisc: return em_parisc_str;
        case em_sparc32plus: return em_sparc32plus_str;
        case em_ppc: return em_ppc_str;
        case em_ppc64: return em_ppc64_str;
        case em_spu: return em_spu_str;
        case em_arm: return em_arm_str;
        case em_sh: return em_sh_str;
        case em_sparcv9: return em_sparcv9_str;
        case em_h8_300: return em_h8_300_str;
        case em_ia_64: return em_ia_64_str;
        case em_x86_64: return em_x86_64_str;
        case em_s390: return em_s390_str;
        case em_cris: return em_cris_str;
        case em_v850: return em_v850_str;
        case em_m32r: return em_m32r_str;
        case em_mn10300: return em_mn10300_str;
        case em_openrisc: return em_openrisc_str;
        case em_blackfin: return em_blackfin_str;
        case em_altera_nios2: return em_altera_nios2_str;
        case em_ti_c6000: return em_ti_c6000_str;
        case em_aarch64: return em_aarch64_str;
        case em_frv: return em_frv_str;
        case em_avr32: return em_avr32_str;
        case em_alpha: return em_alpha_str;
        case em_cygnus_v850: return em_cygnus_v850_str;
        case em_cygnus_m32r: return em_cygnus_m32r_str;
        case em_s390_old: return em_s390_old_str;
        case em_cygnus_mn10300: return em_cygnus_mn10300_str;
        default: return "Unknown e_machine";
    }
}

elf64_sword
elf_file_print_header(struct elf_file_t *ef)
{
    if (!ef)
        return ELF_ERROR_INVALID_ARG;

    if (ef->valid != ELF_TRUE)
        return ELF_ERROR_INVALID_FILE;

    DEBUG("ELF Header:\n");
    DEBUG("  %-35s %X %c %c %c\n", "Magic:", ef->ehdr->e_ident[ei_mag0]
          , ef->ehdr->e_ident[ei_mag1]
          , ef->ehdr->e_ident[ei_mag2]
          , ef->ehdr->e_ident[ei_mag3]);

    DEBUG("  %-35s %s\n", "Class:", ei_class_to_str(ef->ehdr->e_ident[ei_class]));
    DEBUG("  %-35s %s\n", "Data:", ei_data_to_str(ef->ehdr->e_ident[ei_data]));
    DEBUG("  %-35s %s\n", "Version:", version_to_str(ef->ehdr->e_ident[ei_version]));
    DEBUG("  %-35s %s\n", "OS/ABI:", ei_osabi_to_str(ef->ehdr->e_ident[ei_osabi]));
    DEBUG("  %-35s %d\n", "ABI Version:", ef->ehdr->e_ident[ei_abiversion]);
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

    return ELF_SUCCESS;
}

/******************************************************************************/
/* ELF Section Header Table                                                   */
/******************************************************************************/

const char *
sh_type_to_str(elf64_word value)
{
    switch (value)
    {
        case sht_null: return sht_null_str;
        case sht_progbits: return sht_progbits_str;
        case sht_symtab: return sht_symtab_str;
        case sht_strtab: return sht_strtab_str;
        case sht_rela: return sht_rela_str;
        case sht_hash: return sht_hash_str;
        case sht_dynamic: return sht_dynamic_str;
        case sht_note: return sht_note_str;
        case sht_nobits: return sht_nobits_str;
        case sht_rel: return sht_rel_str;
        case sht_shlib: return sht_shlib_str;
        case sht_dynsym: return sht_dynsym_str;
        case sht_loos: return sht_loos_str;
        case sht_hios: return sht_hios_str;
        case sht_loproc: return sht_loproc_str;
        case sht_hiproc: return sht_hiproc_str;
        default: return "Unknown sh_type";
    }
}

elf64_sword
sh_flags_is_writable(struct elf_shdr *shdr)
{
    if (!shdr)
        return ELF_ERROR_INVALID_ARG;

    return (shdr->sh_flags & shf_write) != 0 ? ELF_TRUE : ELF_FALSE;
}

elf64_sword
sh_flags_is_allocated(struct elf_shdr *shdr)
{
    if (!shdr)
        return ELF_ERROR_INVALID_ARG;

    return (shdr->sh_flags & shf_alloc) != 0 ? ELF_TRUE : ELF_FALSE;
}

elf64_sword
sh_flags_is_executable(struct elf_shdr *shdr)
{
    if (!shdr)
        return ELF_ERROR_INVALID_ARG;

    return (shdr->sh_flags & shf_execinstr) != 0 ? ELF_TRUE : ELF_FALSE;
}

elf64_sword
elf_section_header(struct elf_file_t *ef,
                   elf64_word index,
                   struct elf_shdr **shdr)
{
    if (!ef || !ef->ehdr || !ef->shdrtab || !shdr)
        return ELF_ERROR_INVALID_ARG;

    if (index >= ef->ehdr->e_shnum)
        return ELF_ERROR_INVALID_INDEX;

    *shdr = &(ef->shdrtab[index]);

    return ELF_SUCCESS;
}

elf64_sword
elf_print_section_header_table(struct elf_file_t *ef)
{
    elf64_word i = 0;
    elf64_sword ret = 0;

    if (!ef)
        return ELF_ERROR_INVALID_ARG;

    if (ef->valid != ELF_TRUE)
        return ELF_ERROR_INVALID_FILE;

    for (i = 0; i < ef->ehdr->e_shnum; i++)
    {
        struct elf_shdr *shdr = 0;

        ret = elf_section_header(ef, i, &shdr);
        if (ret != ELF_SUCCESS)
            return ret;

        ret = elf_print_section_header(ef, shdr);
        if (ret != ELF_SUCCESS)
            return ret;
    }

    return ELF_SUCCESS;
}

elf64_sword
elf_print_section_header(struct elf_file_t *ef,
                         struct elf_shdr *shdr)
{
    elf64_sword ret = 0;
    struct e_string section_name = {0};

    if (!ef || !shdr)
        return ELF_ERROR_INVALID_ARG;

    if (ef->valid != ELF_TRUE)
        return ELF_ERROR_INVALID_FILE;

    ret = elf_section_name_string(ef, shdr, &section_name);
    if (ret != ELF_SUCCESS)
        return ret;

    DEBUG("Section Header: %s\n", section_name.buf);
    DEBUG("  %-35s %s\n", "Type:", sh_type_to_str(shdr->sh_type));
    DEBUG("  %-35s ", "Flags:");

    if (sh_flags_is_writable(shdr) == ELF_TRUE) INFO("W ");
    if (sh_flags_is_allocated(shdr) == ELF_TRUE) INFO("A ");
    if (sh_flags_is_executable(shdr) == ELF_TRUE) INFO("E ");

    INFO("\n");
    DEBUG("  %-35s 0x%" PRIu64 "\n", "Address:", shdr->sh_addr);
    DEBUG("  %-35s 0x%" PRIu64 "\n", "Offset:", shdr->sh_offset);
    DEBUG("  %-35s %" PRIu64 " (bytes)\n", "Size:", shdr->sh_size);
    DEBUG("  %-35s %u\n", "Linked Section:", shdr->sh_link);
    DEBUG("  %-35s %u\n", "Info:", shdr->sh_info);
    DEBUG("  %-35s %" PRIu64 "\n", "Address Alignment:", shdr->sh_addralign);
    DEBUG("  %-35s %" PRIu64 "\n", "Entry Size:", shdr->sh_entsize);

    DEBUG("\n");

    return ELF_SUCCESS;
}

/******************************************************************************/
/* Section Name String Table                                                  */
/******************************************************************************/

elf64_sword
elf_string_table_entry(struct elf_file_t *ef,
                       struct elf_shdr *strtab,
                       elf64_word offset,
                       struct e_string *str)
{
    char *buf = 0;
    elf64_word i = 0;
    elf64_sword ret = 0;
    elf64_sword max = 0;
    elf64_sword length = 0;

    if (!ef || !strtab || !str)
        return ELF_ERROR_INVALID_ARG;

    if (ef->valid != ELF_TRUE)
        return ELF_ERROR_INVALID_FILE;

    if (offset > strtab->sh_size)
        return ELF_ERROR_INVALID_OFFSET;

    buf = ef->file + strtab->sh_offset + offset;
    max = strtab->sh_size - offset;

    for (i = 0; i < max; i++, length++)
    {
        if (buf[i] == 0)
            break;
    }

    if (i == max)
        return ELF_ERROR_INVALID_STRING_TABLE;

    str->buf = buf;
    str->len = length;

    return ELF_SUCCESS;
}

elf64_sword
elf_section_name_string(struct elf_file_t *ef,
                        struct elf_shdr *shdr,
                        struct e_string *str)
{
    if (!ef || !shdr || !str)
        return ELF_ERROR_INVALID_ARG;

    if (ef->valid != ELF_TRUE)
        return ELF_ERROR_INVALID_FILE;

    return elf_string_table_entry(ef, ef->shstrtab, shdr->sh_name, str);
}

/******************************************************************************/
/* ELF Dynamic Symbol Table                                                   */
/******************************************************************************/

const char *
stb_to_str(elf64_word value)
{
    switch (ELF_SYM_BIND(value))
    {
        case stb_local: return stb_local_str;
        case stb_global: return stb_global_str;
        case stb_weak: return stb_weak_str;
        case stb_loos: return stb_loos_str;
        case stb_hios: return stb_hios_str;
        case stb_loproc: return stb_loproc_str;
        case stb_hiproc: return stb_hiproc_str;
        default: return "Unknown st_info (bind)";
    }
}

const char *
stt_to_str(elf64_word value)
{
    switch (ELF_SYM_TYPE(value))
    {
        case stt_notype: return stt_notype_str;
        case stt_object: return stt_object_str;
        case stt_func: return stt_func_str;
        case stt_section: return stt_section_str;
        case stt_file: return stt_file_str;
        case stt_loos: return stt_loos_str;
        case stt_hios: return stt_hios_str;
        case stt_loproc: return stt_loproc_str;
        case stt_hiproc: return stt_hiproc_str;
        default: return "Unknown st_info (bind)";
    }
}

elf64_sword
elf_symbol_by_index(struct elf_file_t *ef,
                    elf64_word index,
                    struct elf_sym **sym)
{
    if (!ef || !sym)
        return ELF_ERROR_INVALID_ARG;

    if (index >= ef->symnum)
        return ELF_ERROR_INVALID_INDEX;

    if (ef->valid != ELF_TRUE)
        return ELF_ERROR_INVALID_FILE;

    *sym = &(ef->symtab[index]);

    return ELF_SUCCESS;
}

elf64_sword
elf_symbol_by_name(struct elf_file_t *ef,
                   struct e_string *name,
                   struct elf_sym **sym)
{
    elf64_sword i = 0;
    elf64_sword ret = 0;

    /* TODO: Use .hash instead of a O(n) loop. */

    if (!ef || !name || !sym)
        return ELF_ERROR_INVALID_ARG;

    if (ef->valid != ELF_TRUE)
        return ELF_ERROR_INVALID_FILE;

    for (i = 0; i < ef->symnum; i++)
    {
        struct elf_sym *sym = 0;
        struct e_string str = {0};

        ret = elf_symbol_by_index(ef, i, &sym);
        if (ret != ELF_SUCCESS)
            return ret;

        ret = elf_string_table_entry(ef, ef->strtab, sym->st_name, &str);
        if (ret != ELF_SUCCESS)
            return ret;

        ret = elf_strcmp(name, &str);
        if (ret == ELF_FALSE) continue;
        if (ret == ELF_TRUE) break;
        return ret;
    }

    if (i != ef->symnum)
    {
        *sym = &(ef->symtab[i]);
        return ELF_SUCCESS;
    }

    return ELF_ERROR_NO_SUCH_SYMBOL;
}

elf64_sword
elf_symbol_by_name_global(struct elf_file_t *efl,
                          struct e_string *name,
                          struct elf_file_t **efr,
                          struct elf_sym **sym)
{
    elf64_sword i = 0;
    elf64_sword ret = 0;
    struct elf_sym *tmpsym = 0;
    struct elf_file_t *tmpef = efl;

    if (!efl || !name || !efr || !sym)
        return ELF_ERROR_INVALID_ARG;

    if (efl->valid != ELF_TRUE)
        return ELF_ERROR_INVALID_FILE;

    ret = elf_symbol_by_name(tmpef, name, &tmpsym);
    switch (ret)
    {
        case ELF_SUCCESS:
            if (tmpsym->st_value != 0)
                goto found;

        case ELF_ERROR_NO_SUCH_SYMBOL:
            break;

        default:
            return ret;
    };

    for (i = 0; i < efl->efnum; i++)
    {
        tmpef = efl->eftab[i];

        ret = elf_symbol_by_name(tmpef, name, &tmpsym);
        switch (ret)
        {
            case ELF_SUCCESS:
                if (tmpsym->st_value != 0)
                    goto found;

            case ELF_ERROR_NO_SUCH_SYMBOL:
                break;

            default:
                return ret;
        };
    }

    return ELF_ERROR_NO_SUCH_SYMBOL;

found:

    *efr = tmpef;
    *sym = tmpsym;

    return ELF_SUCCESS;
}

elf64_sword
elf_resolve_symbol(struct elf_file_t *ef,
                   struct e_string *name,
                   void **addr)
{
    elf64_sword ret = 0;
    struct elf_sym *sym = 0;
    struct elf_file_t *efr = 0;

    if (!ef || !name || !addr)
        return ELF_ERROR_INVALID_ARG;

    if (ef->valid != ELF_TRUE)
        return ELF_ERROR_INVALID_FILE;

    ret = elf_symbol_by_name_global(ef, name, &efr, &sym);
    if (ret != ELF_SUCCESS)
        return ret;

    *addr = efr->exec + sym->st_value;

    return ELF_SUCCESS;
}

elf64_sword
elf_print_sym_table(struct elf_file_t *ef)
{
    elf64_sword i = 0;
    elf64_sword ret = 0;

    if (!ef)
        return ELF_ERROR_INVALID_ARG;

    if (ef->valid != ELF_TRUE)
        return ELF_ERROR_INVALID_FILE;

    for (i = 0; i < ef->symnum; i++)
    {
        struct elf_sym *sym = 0;

        ret = elf_symbol_by_index(ef, i, &sym);
        if (ret != ELF_SUCCESS)
            return ret;

        ret = elf_print_sym(ef, sym);
        if (ret != ELF_SUCCESS)
            return ret;
    }

    DEBUG("\n");

    return ELF_SUCCESS;
}

elf64_sword
elf_print_sym(struct elf_file_t *ef,
              struct elf_sym *sym)
{
    elf64_sword ret = 0;
    struct e_string str = {0};

    if (!ef || !sym)
        return ELF_ERROR_INVALID_ARG;

    if (ef->valid != ELF_TRUE)
        return ELF_ERROR_INVALID_FILE;

    ret = elf_string_table_entry(ef, ef->strtab, sym->st_name, &str);
    if (ret != ELF_SUCCESS)
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

    return ELF_SUCCESS;
}

/******************************************************************************/
/* ELF Relocations                                                            */
/******************************************************************************/

const char *
rel_type_to_str(elf64_xword value)
{
    switch (ELF_REL_TYPE(value))
    {
        case R_X86_64_64: return R_X86_64_64_STR;
        case R_X86_64_GLOB_DAT: return R_X86_64_GLOB_DAT_STR;
        case R_X86_64_JUMP_SLOT: return R_X86_64_JUMP_SLOT_STR;
        case R_X86_64_RELATIVE: return R_X86_64_RELATIVE_STR;
        default: return "Unknown ELF_REL_TYPE(r_info)";
    }
}

elf64_sword
elf_relocate_symbol(struct elf_file_t *ef,
                    struct elf_rel *rel)
{
    elf64_addr *ptr = 0;
    elf64_sword ret = 0;
    struct elf_sym *sym = 0;
    struct e_string name = {0};
    struct elf_file_t *efr = 0;

    if (!ef || !rel)
        return ELF_ERROR_INVALID_ARG;

    if (ef->valid != ELF_TRUE)
        return ELF_ERROR_INVALID_FILE;

    ret = elf_symbol_by_index(ef, ELF_REL_SYM(rel->r_info), &sym);
    if (ret != ELF_SUCCESS)
        return ret;

    ret = elf_string_table_entry(ef, ef->strtab, sym->st_name, &name);
    if (ret != ELF_SUCCESS)
        return ret;

    ret = elf_symbol_by_name_global(ef, &name, &efr, &sym);
    if (ret != ELF_SUCCESS)
        return ret;

    ptr = (elf64_addr *)(ef->exec + rel->r_offset);

    if (ptr > (elf64_addr *)(ef->exec + ef->esize))
        return ELF_ERROR_INVALID_FILE;

    /* TODO: Remove the relocation for R_X86_64_JUMP_SLOT, and instead
       fill in the address of a function that does the relocation and
       then jumps to the value that should have been there. Called
       lazy loading */

    switch (ELF_REL_TYPE(rel->r_info))
    {
        case R_X86_64_GLOB_DAT:
        case R_X86_64_JUMP_SLOT:
            *ptr = (elf64_addr)(efr->exec + sym->st_value);
            break;

        default:
            return ELF_ERROR_INVALID_RELOCATION_TYPE;
    }

    return ELF_SUCCESS;
}

elf64_sword
elf_relocate_symbol_addend(struct elf_file_t *ef,
                           struct elf_rela *rela)
{
    elf64_addr *ptr = 0;
    elf64_sword ret = 0;
    struct elf_sym *sym = 0;
    struct e_string name = {0};
    struct elf_file_t *efr = 0;

    if (!ef || !rela)
        return ELF_ERROR_INVALID_ARG;

    if (ef->valid != ELF_TRUE)
        return ELF_ERROR_INVALID_FILE;

    ret = elf_symbol_by_index(ef, ELF_REL_SYM(rela->r_info), &sym);
    if (ret != ELF_SUCCESS)
        return ret;

    ret = elf_string_table_entry(ef, ef->strtab, sym->st_name, &name);
    if (ret != ELF_SUCCESS)
        return ret;

    ret = elf_symbol_by_name_global(ef, &name, &efr, &sym);
    if (ret != ELF_SUCCESS)
        return ret;

    ptr = (elf64_addr *)(ef->exec + rela->r_offset);

    if (ptr > (elf64_addr *)(ef->exec + ef->esize))
        return ELF_ERROR_INVALID_FILE;

    /* TODO: Remove the relocation for R_X86_64_JUMP_SLOT, and instead
       fill in the address of a function that does the relocation and
       then jumps to the value that should have been there. Called
       lazy loading */

    switch (ELF_REL_TYPE(rela->r_info))
    {
        case R_X86_64_64:
            *ptr = (elf64_addr)(efr->exec + sym->st_value + rela->r_addend);
            break;

        case R_X86_64_GLOB_DAT:
        case R_X86_64_JUMP_SLOT:
            *ptr = (elf64_addr)(efr->exec + sym->st_value);
            break;

        case R_X86_64_RELATIVE:
            *ptr = (elf64_addr)(efr->exec + rela->r_addend);

        default:
            return ELF_ERROR_INVALID_RELOCATION_TYPE;
    }

    return ELF_SUCCESS;
}

elf64_sword
elf_relocate_symbols(struct elf_file_t *ef)
{
    elf64_word t = 0;
    elf64_word r = 0;
    elf64_sword ret = 0;

    if (!ef)
        return ELF_ERROR_INVALID_ARG;

    if (ef->valid != ELF_TRUE)
        return ELF_ERROR_INVALID_FILE;

    for (t = 0; t < ef->num_rel; t++)
    {
        for (r = 0; r < ef->reltab[t].num; r++)
        {
            ret = elf_relocate_symbol(ef, &(ef->reltab[t].tab[r]));
            if (ret != ELF_SUCCESS)
                return ret;
        }
    }

    for (t = 0; t < ef->num_rela; t++)
    {
        for (r = 0; r < ef->relatab[t].num; r++)
        {
            ret = elf_relocate_symbol_addend(ef, &(ef->relatab[t].tab[r]));
            if (ret != ELF_SUCCESS)
                return ret;
        }
    }

    return ELF_SUCCESS;
}

elf64_sword
elf_print_relocation(struct elf_rel *rel)
{
    elf64_sword ret = 0;

    if (!rel)
        return ELF_ERROR_INVALID_ARG;

#ifdef PRINT_DETAILED_REL

    DEBUG("Relocation:\n");
    DEBUG("  %-35s 0x%08" PRIu64 "\n", "Offset:", rel->r_offset);
    DEBUG("  %-35s %" PRId64 "\n", "Symbol:", ELF_REL_SYM(rel->r_info));
    DEBUG("  %-35s %s\n", "Type:", rel_type_to_str(rel->r_info));

    DEBUG("\n");

#else

    DEBUG("Relocation: %-20s 0x%08" PRIu64 " %04" PRId64 "\n", rel_type_to_str(rel->r_info),
          rel->r_offset,
          ELF_REL_SYM(rel->r_info));

#endif

    return ELF_SUCCESS;
}

elf64_sword
elf_print_relocation_addend(struct elf_rela *rela)
{
    elf64_sword ret = 0;

    if (!rela)
        return ELF_ERROR_INVALID_ARG;

#ifdef PRINT_DETAILED_REL

    DEBUG("Relocation:\n");
    DEBUG("  %-35s 0x%08" PRIu64 "\n", "Offset:", rela->r_offset);
    DEBUG("  %-35s %" PRId64 "\n", "Symbol:", ELF_REL_SYM(rela->r_info));
    DEBUG("  %-35s %s\n", "Type:", rel_type_to_str(rela->r_info));
    DEBUG("  %-35s 0x%" PRIu64 "\n", "Addend:", rela->r_addend);

    DEBUG("\n");

#else

    DEBUG("Relocation: %-20s 0x%08" PRIu64 " %04" PRId64 " 0x%08" PRIu64 "\n", rel_type_to_str(rela->r_info),
          rela->r_offset,
          ELF_REL_SYM(rela->r_info),
          rela->r_addend);

#endif

    return ELF_SUCCESS;
}

elf64_sword
elf_print_relocations(struct elf_file_t *ef)
{
    elf64_word t = 0;
    elf64_word r = 0;
    elf64_sword ret = 0;

    if (!ef)
        return ELF_ERROR_INVALID_ARG;

    if (ef->valid != ELF_TRUE)
        return ELF_ERROR_INVALID_FILE;

    for (t = 0; t < ef->num_rel; t++)
    {
        for (r = 0; r < ef->reltab[t].num; r++)
        {
            ret = elf_print_relocation(&(ef->reltab[t].tab[r]));
            if (ret != ELF_SUCCESS)
                return ret;
        }
    }

    for (t = 0; t < ef->num_rela; t++)
    {
        for (r = 0; r < ef->relatab[t].num; r++)
        {
            ret = elf_print_relocation_addend(&(ef->relatab[t].tab[r]));
            if (ret != ELF_SUCCESS)
                return ret;
        }
    }

    DEBUG("\n");

    return ELF_SUCCESS;
}

/******************************************************************************/
/* ELF Program Header                                                         */
/******************************************************************************/

/* TODO: Need function to return a map that explains how to set the permissions
   of the memory used to load the ELF file. This way, portions of the RAM that
   holds the program can be RW and other portions can be RE */

const char *
p_type_to_str(elf64_word value)
{
    switch (value)
    {
        case pt_null: return pt_null_str;
        case pt_load: return pt_load_str;
        case pt_dynamic: return pt_dynamic_str;
        case pt_interp: return pt_interp_str;
        case pt_note: return pt_note_str;
        case pt_shlib: return pt_shlib_str;
        case pt_phdr: return pt_phdr_str;
        case pt_loos: return pt_loos_str;
        case pt_hios: return pt_hios_str;
        case pt_loproc: return pt_loproc_str;
        case pt_hiproc: return pt_hiproc_str;
        default: return "Unknown p_type";
    }
}

elf64_sword
p_flags_is_executable(struct elf_phdr *phdr)
{
    if (!phdr)
        return ELF_ERROR_INVALID_ARG;

    return (phdr->p_flags & pf_x) != 0 ? ELF_TRUE : ELF_FALSE;
}

elf64_sword
p_flags_is_writable(struct elf_phdr *phdr)
{
    if (!phdr)
        return ELF_ERROR_INVALID_ARG;

    return (phdr->p_flags & pf_w) != 0 ? ELF_TRUE : ELF_FALSE;
}

elf64_sword
p_flags_is_readable(struct elf_phdr *phdr)
{
    if (!phdr)
        return ELF_ERROR_INVALID_ARG;

    return (phdr->p_flags & pf_r) != 0 ? ELF_TRUE : ELF_FALSE;
}

elf64_sword
elf_program_header(struct elf_file_t *ef,
                   elf64_word index,
                   struct elf_phdr **phdr)
{
    if (!ef || !ef->ehdr || !ef->phdrtab || !phdr)
        return ELF_ERROR_INVALID_ARG;

    if (index >= ef->ehdr->e_phnum)
        return ELF_ERROR_INVALID_INDEX;

    *phdr = &(ef->phdrtab[index]);

    return ELF_SUCCESS;
}

elf64_sxword
elf_total_exec_size(struct elf_file_t *ef)
{
    elf64_word i = 0;
    elf64_sword ret = 0;
    elf64_sxword total_size = 0;

    if (!ef)
        return ELF_ERROR_INVALID_ARG;

    if (ef->valid != ELF_TRUE)
        return ELF_ERROR_INVALID_FILE;

    for (i = 0; i < ef->ehdr->e_phnum; i++)
    {
        elf64_sxword size = 0;
        struct elf_phdr *phdr = 0;

        ret = elf_program_header(ef, i, &phdr);
        if (ret != ELF_SUCCESS)
            return ret;

        size = phdr->p_vaddr + phdr->p_memsz;

        if (size > total_size)
            total_size = size;
    }

    return total_size;
}

elf64_sword
elf_load_segments(struct elf_file_t *ef)
{
    elf64_word i = 0;
    elf64_sword ret = 0;

    if (!ef)
        return ELF_ERROR_INVALID_ARG;

    if (ef->valid != ELF_TRUE)
        return ELF_ERROR_INVALID_FILE;

    for (i = 0; i < ef->ehdr->e_phnum; i++)
    {
        struct elf_phdr *phdr = 0;

        ret = elf_program_header(ef, i, &phdr);
        if (ret != ELF_SUCCESS)
            return ret;

        ret = elf_load_segment(ef, phdr);
        if (ret != ELF_SUCCESS)
            return ret;
    }

    return ELF_SUCCESS;
}

elf64_sword
elf_load_segment(struct elf_file_t *ef,
                 struct elf_phdr *phdr)
{
    char *exec = 0;
    char *file = 0;
    elf64_word i = 0;

    if (!ef || !phdr)
        return ELF_ERROR_INVALID_ARG;

    if (ef->valid != ELF_TRUE)
        return ELF_ERROR_INVALID_FILE;

    if (phdr->p_vaddr + phdr->p_memsz > ef->esize)
        return ELF_ERROR_INVALID_PH_MEMSZ;

    exec = ef->exec + phdr->p_vaddr;
    file = ef->file + phdr->p_offset;

    for (i = 0; i < phdr->p_filesz; i++)
        exec[i] = file[i];

    return ELF_SUCCESS;
}

elf64_sword
elf_print_program_header_table(struct elf_file_t *ef)
{
    elf64_word i = 0;
    elf64_sword ret = 0;

    if (!ef)
        return ELF_ERROR_INVALID_ARG;

    if (ef->valid != ELF_TRUE)
        return ELF_ERROR_INVALID_FILE;

    for (i = 0; i < ef->ehdr->e_phnum; i++)
    {
        struct elf_phdr *phdr = 0;

        ret = elf_program_header(ef, i, &phdr);
        if (ret != ELF_SUCCESS)
            return ret;

        ret = elf_print_program_header(ef, phdr);
        if (ret != ELF_SUCCESS)
            return ret;
    }

    return ELF_SUCCESS;
}

elf64_sword
elf_print_program_header(struct elf_file_t *ef,
                         struct elf_phdr *phdr)
{
    elf64_sword ret = 0;

    if (!ef || !phdr)
        return ELF_ERROR_INVALID_ARG;

    if (ef->valid != ELF_TRUE)
        return ELF_ERROR_INVALID_FILE;

    DEBUG("Program Header:\n");
    DEBUG("  %-35s %s\n", "Type:", p_type_to_str(phdr->p_type));
    DEBUG("  %-35s ", "Flags:");

    if (p_flags_is_executable(phdr) == ELF_TRUE) INFO("E ");
    if (p_flags_is_writable(phdr) == ELF_TRUE) INFO("W ");
    if (p_flags_is_readable(phdr) == ELF_TRUE) INFO("R ");

    INFO("\n");
    DEBUG("  %-35s 0x%" PRIu64 "\n", "Offset:", phdr->p_offset);
    DEBUG("  %-35s 0x%" PRIu64 "\n", "Virtual Address:", phdr->p_vaddr);
    DEBUG("  %-35s 0x%" PRIu64 "\n", "Physical Address:", phdr->p_paddr);
    DEBUG("  %-35s %" PRIu64 " (bytes)\n", "File Size:", phdr->p_filesz);
    DEBUG("  %-35s %" PRIu64 " (bytes)\n", "Exec Size:", phdr->p_memsz);
    DEBUG("  %-35s 0x%" PRIu64 "\n", "Alignment:", phdr->p_align);

    DEBUG("\n");

    return ELF_SUCCESS;
}
