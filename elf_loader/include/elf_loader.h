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

#ifndef ELF_LOADER_H
#define ELF_LOADER_H

#include <stdint.h>

#pragma pack(push, 1)

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/
/* ELF Defines                                                                */
/******************************************************************************/

#ifndef ELF_MAX_MODULES
#define ELF_MAX_MODULES 100
#endif

#ifndef ELF_MAX_RELTAB
#define ELF_MAX_RELTAB 100
#endif

/******************************************************************************/
/* ELF Data Types                                                             */
/******************************************************************************/

/*
 * Data Representation
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 2
 */

typedef uint64_t elf64_addr;
typedef uint64_t elf64_off;
typedef uint16_t elf64_half;
typedef uint32_t elf64_word;
typedef int32_t elf64_sword;
typedef uint64_t elf64_xword;
typedef int64_t elf64_sxword;

#define ELF_TRUE ((elf64_sword)1)
#define ELF_FALSE ((elf64_sword)0)

/******************************************************************************/
/* ELF Error Codes                                                            */
/******************************************************************************/

/*
 * ELF error codes
 *
 * The following define the different error codes that this library might
 * provide given bad input.
 */
#define ELF_SUCCESS ((elf64_sword)0)
#define ELF_ERROR_INVALID_ARG ((elf64_sword)-1)
#define ELF_ERROR_INVALID_FILE ((elf64_sword)-2)
#define ELF_ERROR_INVALID_INDEX ((elf64_sword)-3)
#define ELF_ERROR_INVALID_OFFSET ((elf64_sword)-4)
#define ELF_ERROR_INVALID_STRING ((elf64_sword)-5)
#define ELF_ERROR_INVALID_EI_MAG0 ((elf64_sword)-101)
#define ELF_ERROR_INVALID_EI_MAG1 ((elf64_sword)-102)
#define ELF_ERROR_INVALID_EI_MAG2 ((elf64_sword)-103)
#define ELF_ERROR_INVALID_EI_MAG3 ((elf64_sword)-104)
#define ELF_ERROR_INVALID_EI_CLASS ((elf64_sword)-105)
#define ELF_ERROR_INVALID_EI_DATA ((elf64_sword)-106)
#define ELF_ERROR_INVALID_EI_VERSION ((elf64_sword)-107)
#define ELF_ERROR_INVALID_EI_OSABI ((elf64_sword)-108)
#define ELF_ERROR_INVALID_EI_ABIVERSION ((elf64_sword)-109)
#define ELF_ERROR_INVALID_E_TYPE ((elf64_sword)-110)
#define ELF_ERROR_INVALID_E_MACHINE ((elf64_sword)-111)
#define ELF_ERROR_INVALID_E_ENTRY ((elf64_sword)-112)
#define ELF_ERROR_INVALID_E_PHOFF ((elf64_sword)-113)
#define ELF_ERROR_INVALID_E_SHOFF ((elf64_sword)-114)
#define ELF_ERROR_INVALID_E_FLAGS ((elf64_sword)-115)
#define ELF_ERROR_INVALID_E_EHSIZE ((elf64_sword)-116)
#define ELF_ERROR_INVALID_E_PHENTSIZE ((elf64_sword)-117)
#define ELF_ERROR_INVALID_E_PHNUM ((elf64_sword)-118)
#define ELF_ERROR_INVALID_E_SHENTSIZE ((elf64_sword)-119)
#define ELF_ERROR_INVALID_E_SHNUM ((elf64_sword)-120)
#define ELF_ERROR_INVALID_E_SHSTRNDX ((elf64_sword)-121)
#define ELF_ERROR_INVALID_PHT ((elf64_sword)-122)
#define ELF_ERROR_INVALID_SHT ((elf64_sword)-123)
#define ELF_ERROR_INVALID_SH_NAME ((elf64_sword)-200)
#define ELF_ERROR_INVALID_SH_TYPE ((elf64_sword)-201)
#define ELF_ERROR_INVALID_SH_FLAGS ((elf64_sword)-202)
#define ELF_ERROR_INVALID_SH_ADDR ((elf64_sword)-203)
#define ELF_ERROR_INVALID_SH_OFFSET ((elf64_sword)-204)
#define ELF_ERROR_INVALID_SH_SIZE ((elf64_sword)-205)
#define ELF_ERROR_INVALID_SH_LINK ((elf64_sword)-206)
#define ELF_ERROR_INVALID_SH_INFO ((elf64_sword)-207)
#define ELF_ERROR_INVALID_SH_ADDRALIGN ((elf64_sword)-208)
#define ELF_ERROR_INVALID_SH_ENTSIZE ((elf64_sword)-209)
#define ELF_ERROR_INVALID_PH_TYPE ((elf64_sword)-300)
#define ELF_ERROR_INVALID_PH_FLAGS ((elf64_sword)-301)
#define ELF_ERROR_INVALID_PH_OFFSET ((elf64_sword)-302)
#define ELF_ERROR_INVALID_PH_VADDR ((elf64_sword)-303)
#define ELF_ERROR_INVALID_PH_PADDR ((elf64_sword)-304)
#define ELF_ERROR_INVALID_PH_FILESZ ((elf64_sword)-305)
#define ELF_ERROR_INVALID_PH_MEMSZ ((elf64_sword)-306)
#define ELF_ERROR_INVALID_PH_ALIGN ((elf64_sword)-307)
#define ELF_ERROR_INVALID_STRING_TABLE ((elf64_sword)-400)
#define ELF_ERROR_NO_SUCH_SYMBOL ((elf64_sword)-500)
#define ELF_ERROR_SYMBOL_UNDEFINED ((elf64_sword)-501)
#define ELF_ERROR_LOADER_FULL ((elf64_sword)-600)
#define ELF_ERROR_INVALID_LOADER ((elf64_sword)-601)
#define ELF_ERROR_INVALID_RELOCATION_TYPE ((elf64_sword)-701)

const char *ELF_SUCCESS_STR = "Success (ELF_SUCCESS)";
const char *ELF_ERROR_INVALID_ARG_STR = "Invalid argument (ELF_ERROR_INVALID_ARG)";
const char *ELF_ERROR_INVALID_FILE_STR = "Invalid elf file (ELF_ERROR_INVALID_FILE)";
const char *ELF_ERROR_INVALID_INDEX_STR = "Invalid index (ELF_ERROR_INVALID_INDEX)";
const char *ELF_ERROR_INVALID_OFFSET_STR = "Invalid offset (ELF_ERROR_INVALID_OFFSET)";
const char *ELF_ERROR_INVALID_STRING_STR = "Invliad string (ELF_ERROR_INVALID_STRING)";
const char *ELF_ERROR_INVALID_EI_MAG0_STR = "Invalid magic number (0) in elf header (ELF_ERROR_INVALID_EI_MAG0)";
const char *ELF_ERROR_INVALID_EI_MAG1_STR = "Invalid magic number (1) in elf header (ELF_ERROR_INVALID_EI_MAG1)";
const char *ELF_ERROR_INVALID_EI_MAG2_STR = "Invalid magic number (2) in elf header (ELF_ERROR_INVALID_EI_MAG2)";
const char *ELF_ERROR_INVALID_EI_MAG3_STR = "Invalid magic number (3) in elf header (ELF_ERROR_INVALID_EI_MAG3)";
const char *ELF_ERROR_INVALID_EI_CLASS_STR = "Invalid class field in elf header (ELF_ERROR_INVALID_EI_CLASS)";
const char *ELF_ERROR_INVALID_EI_DATA_STR = "Invalid data field in elf header (ELF_ERROR_INVALID_EI_DATA)";
const char *ELF_ERROR_INVALID_EI_VERSION_STR = "Invalid version in elf header (ELF_ERROR_INVALID_EI_VERSION)";
const char *ELF_ERROR_INVALID_EI_OSABI_STR = "Invalid OS/ABI field in elf header (ELF_ERROR_INVALID_EI_OSABI)";
const char *ELF_ERROR_INVALID_EI_ABIVERSION_STR = "Invalid ABI version in elf header (ELF_ERROR_INVALID_EI_ABIVERSION)";
const char *ELF_ERROR_INVALID_E_TYPE_STR = "Invalid type field in elf header (ELF_ERROR_INVALID_E_TYPE)";
const char *ELF_ERROR_INVALID_E_MACHINE_STR = "Invalid machine ID in elf header (ELF_ERROR_INVALID_E_MACHINE)";
const char *ELF_ERROR_INVALID_E_ENTRY_STR = "Invalid entry point in elf header (ELF_ERROR_INVALID_E_ENTRY)";
const char *ELF_ERROR_INVALID_E_PHOFF_STR = "Invalid program header offset in elf header (ELF_ERROR_INVALID_E_PHOFF)";
const char *ELF_ERROR_INVALID_E_SHOFF_STR = "Invalid section header offset in elf header (ELF_ERROR_INVALID_E_SHOFF)";
const char *ELF_ERROR_INVALID_E_FLAGS_STR = "Invalid flags in elf header (ELF_ERROR_INVALID_E_FLAGS)";
const char *ELF_ERROR_INVALID_E_EHSIZE_STR = "Invalid header size in elf header (ELF_ERROR_INVALID_E_EHSIZE)";
const char *ELF_ERROR_INVALID_E_PHENTSIZE_STR = "Invalid program entry header size in elf header (ELF_ERROR_INVALID_E_PHENTSIZE)";
const char *ELF_ERROR_INVALID_E_PHNUM_STR = "Invalid number of program entries in elf header (ELF_ERROR_INVALID_E_PHNUM)";
const char *ELF_ERROR_INVALID_E_SHENTSIZE_STR = "Invalid section header size in elf header (ELF_ERROR_INVALID_E_SHENTSIZE)";
const char *ELF_ERROR_INVALID_E_SHNUM_STR = "Invalid number of section entries in elf header (ELF_ERROR_INVALID_E_SHNUM)";
const char *ELF_ERROR_INVALID_E_SHSTRNDX_STR = "Invalid section name string index table in elf header (ELF_ERROR_INVALID_E_SHSTRNDX)";
const char *ELF_ERROR_INVALID_PHT_STR = "Invalid program header table (ELF_ERROR_INVALID_PHT)";
const char *ELF_ERROR_INVALID_SHT_STR = "Invalid section header table (ELF_ERROR_INVALID_SHT)";
const char *ELF_ERROR_INVALID_SH_NAME_STR = "Invalid section name (ELF_ERROR_INVALID_SH_NAME)";
const char *ELF_ERROR_INVALID_SH_TYPE_STR = "Invalid section type (ELF_ERROR_INVALID_SH_TYPE)";
const char *ELF_ERROR_INVALID_SH_FLAGS_STR = "Invalid section flags (ELF_ERROR_INVALID_SH_FLAGS)";
const char *ELF_ERROR_INVALID_SH_ADDR_STR = "Invalid section address (ELF_ERROR_INVALID_SH_ADDR)";
const char *ELF_ERROR_INVALID_SH_OFFSET_STR = "Invalid section offset (ELF_ERROR_INVALID_SH_OFFSET)";
const char *ELF_ERROR_INVALID_SH_SIZE_STR = "Invalid section size (ELF_ERROR_INVALID_SH_SIZE)";
const char *ELF_ERROR_INVALID_SH_LINK_STR = "Invalid section link (ELF_ERROR_INVALID_SH_LINK)";
const char *ELF_ERROR_INVALID_SH_INFO_STR = "Invalid section info (ELF_ERROR_INVALID_SH_INFO)";
const char *ELF_ERROR_INVALID_SH_ADDRALIGN_STR = "Invalid section address alignment (ELF_ERROR_INVALID_SH_ADDRALIGN)";
const char *ELF_ERROR_INVALID_SH_ENTSIZE_STR = "Invalid section entry size (ELF_ERROR_INVALID_SH_ENTSIZE)";
const char *ELF_ERROR_INVALID_PH_TYPE_STR = "Invalid segment type (ELF_ERROR_INVALID_PH_TYPE)";
const char *ELF_ERROR_INVALID_PH_FLAGS_STR = "Invalid segment flags (ELF_ERROR_INVALID_PH_FLAGS)";
const char *ELF_ERROR_INVALID_PH_OFFSET_STR = "Invalid segment offset (ELF_ERROR_INVALID_PH_OFFSET)";
const char *ELF_ERROR_INVALID_PH_VADDR_STR = "Invalid segment vaddr (ELF_ERROR_INVALID_PH_VADDR)";
const char *ELF_ERROR_INVALID_PH_PADDR_STR = "Invalid segment paddr (ELF_ERROR_INVALID_PH_PADDR)";
const char *ELF_ERROR_INVALID_PH_FILESZ_STR = "Invalid segment file size (ELF_ERROR_INVALID_PH_FILESZ)";
const char *ELF_ERROR_INVALID_PH_MEMSZ_STR = "Invalid segment mem size (ELF_ERROR_INVALID_PH_MEMSZ)";
const char *ELF_ERROR_INVALID_PH_ALIGN_STR = "Invalid segment alignment (ELF_ERROR_INVALID_PH_ALIGN)";
const char *ELF_ERROR_INVALID_STRING_TABLE_STR = "Invalid string table (ELF_ERROR_INVALID_STRING_TABLE)";
const char *ELF_ERROR_NO_SUCH_SYMBOL_STR = "Unable to find symbol (ELF_ERROR_NO_SUCH_SYMBOL)";
const char *ELF_ERROR_SYMBOL_UNDEFINED_STR = "Symbol is undefined (ELF_ERROR_SYMBOL_UNDEFINED)";
const char *ELF_ERROR_LOADER_FULL_STR = "Loader is full (ELF_ERROR_LOADER_FULL_STR)";
const char *ELF_ERROR_INVALID_LOADER_STR = "Invalid loader (ELF_ERROR_INVALID_LOADER)";
const char *ELF_ERROR_INVALID_RELOCATION_TYPE_STR = "Invalid relocation type (ELF_ERROR_INVALID_RELOCATION_TYPE)";

const char *
elf_error(elf64_sword value);

/******************************************************************************/
/* ELF File                                                                   */
/******************************************************************************/

struct elf_sym;
struct elf_rel;
struct elf_shdr;
struct elf64_ehdr;

/*
 * Relocation Table
 *
 * The following is used by this API to store information about a symbol
 * table.
 */
struct reltab_t
{
    elf64_sword num;
    struct elf_rel *tab;
};

struct relatab_t
{
    elf64_sword num;
    struct elf_rela *tab;
};

/*
 * ELF File
 *
 * The following is used by this API to store information about the ELF file
 * being used.
 */
struct elf_file_t
{
    char *file;
    char *exec;
    elf64_sword fsize;
    elf64_sword esize;

    struct elf64_ehdr *ehdr;
    struct elf_shdr *shdrtab;
    struct elf_phdr *phdrtab;

    struct elf_shdr *dynsym;
    struct elf_shdr *strtab;
    struct elf_shdr *shstrtab;

    elf64_sword symnum;
    struct elf_sym *symtab;

    elf64_sword efnum;
    struct elf_file_t *eftab[ELF_MAX_MODULES];

    elf64_sword num_rel;
    struct reltab_t reltab[ELF_MAX_RELTAB];

    elf64_sword num_rela;
    struct relatab_t relatab[ELF_MAX_RELTAB];

    elf64_sword valid;
};

elf64_sword
elf_file_init(char *file, elf64_sword fsize, struct elf_file_t *ef);

elf64_sword
elf_file_load(struct elf_file_t *ef, char *exec, elf64_sword esize);

/******************************************************************************/
/* ELF Loader                                                                 */
/******************************************************************************/

struct elf_loader_t
{
    elf64_sword num;
    struct elf_file_t *efs[ELF_MAX_MODULES];
};

elf64_sword
elf_loader_init(struct elf_loader_t *loader);

elf64_sword
elf_loader_add(struct elf_loader_t *loader, struct elf_file_t *ef);

elf64_sword
elf_loader_relocate(struct elf_loader_t *loader);

/******************************************************************************/
/* ELF File Header                                                            */
/******************************************************************************/

/*
 * e_ident indexes
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 3
 */
#define ei_mag0 ((elf64_sword)0)
#define ei_mag1 ((elf64_sword)1)
#define ei_mag2 ((elf64_sword)2)
#define ei_mag3 ((elf64_sword)3)
#define ei_class ((elf64_sword)4)
#define ei_data ((elf64_sword)5)
#define ei_version ((elf64_sword)6)
#define ei_osabi ((elf64_sword)7)
#define ei_abiversion ((elf64_sword)8)
#define ei_pad ((elf64_sword)9)
#define ei_nident ((elf64_sword)16)

/*
 * ELF Class Types
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 5
 */
#define elfclass32 ((unsigned char)1)
#define elfclass64 ((unsigned char)2)

const char *elfclass32_str = "ELF32 (elfclass32)";
const char *elfclass64_str = "ELF64 (elfclass64)";

const char *
ei_class_to_str(unsigned char value);

/*
 * ELF Data Types
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 5
 */
#define elfdata2lsb ((unsigned char)1)
#define elfdata2msb ((unsigned char)2)

const char *elfdata2lsb_str = "2's complement, little endian (elfdata2lsb)";
const char *elfdata2msb_str = "2's complement, big endian (elfdata2msb)";

const char *
ei_data_to_str(unsigned char value);

/*
 * ELF Version
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 4
 */
#define ev_current ((unsigned char)1)

const char *ev_current_str = "1 (ev_current)";

const char *
version_to_str(unsigned char value);

/*
 * ELF OS / ABI Types
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 5
 */
#define elfosabi_sysv ((unsigned char)0)
#define elfosabi_hpux ((unsigned char)1)
#define elfosabi_standalone ((unsigned char)255)

const char *elfosabi_sysv_str = "System V ABI (elfosabi_sysv)";
const char *elfosabi_hpux_str = "HP-UX operating system (elfosabi_hpux)";
const char *elfosabi_standalone_str = "Standalone (elfosabi_standalone)";

const char *
ei_osabi_to_str(unsigned char value);

/*
 * ELF Types
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 5
 */
#define et_none ((elf64_half)0)
#define et_rel ((elf64_half)1)
#define et_exec ((elf64_half)2)
#define et_dyn ((elf64_half)3)
#define et_core ((elf64_half)4)
#define et_loos ((elf64_half)0xFE00)
#define et_hios ((elf64_half)0xFEFF)
#define et_loproc ((elf64_half)0xFF00)
#define et_hiproc ((elf64_half)0xFFFF)

const char *et_none_str = "No file type (et_none)";
const char *et_rel_str = "Relocatable object file (et_rel)";
const char *et_exec_str = "Executable file (et_exec)";
const char *et_dyn_str = "Shared object file (et_dyn)";
const char *et_core_str = "Core file (et_core)";
const char *et_loos_str = "Environment-specific use (et_loos)";
const char *et_hios_str = "Environment-specific use (et_hios)";
const char *et_loproc_str = "Processor-specific use (et_loproc)";
const char *et_hiproc_str = "Processor-specific use (et_hiproc)";

const char *
e_type_to_str(elf64_half value);

/*
 * ELF Machine Codes
 *
 * The following is defined in the Linux kernel sources:
 * linux/include/uapi/linux/elf-em.h
 */
#define em_none ((elf64_half)0)
#define em_m32 ((elf64_half)1)
#define em_sparc ((elf64_half)2)
#define em_386 ((elf64_half)3)
#define em_68k ((elf64_half)4)
#define em_88k ((elf64_half)5)
#define em_486 ((elf64_half)6)
#define em_860 ((elf64_half)7)
#define em_mips ((elf64_half)8)
#define em_mips_rs3_le ((elf64_half)10)
#define em_mips_rs4_be ((elf64_half)11)
#define em_parisc ((elf64_half)15)
#define em_sparc32plus ((elf64_half)18)
#define em_ppc ((elf64_half)20)
#define em_ppc64 ((elf64_half)21)
#define em_spu ((elf64_half)23)
#define em_arm ((elf64_half)40)
#define em_sh ((elf64_half)42)
#define em_sparcv9 ((elf64_half)43)
#define em_h8_300 ((elf64_half)46)
#define em_ia_64 ((elf64_half)50)
#define em_x86_64 ((elf64_half)62)
#define em_s390 ((elf64_half)22)
#define em_cris ((elf64_half)76)
#define em_v850 ((elf64_half)87)
#define em_m32r ((elf64_half)88)
#define em_mn10300 ((elf64_half)89)
#define em_openrisc ((elf64_half)92)
#define em_blackfin ((elf64_half)106)
#define em_altera_nios2 ((elf64_half)113)
#define em_ti_c6000 ((elf64_half)140)
#define em_aarch64 ((elf64_half)183)
#define em_frv ((elf64_half)0x5441)
#define em_avr32 ((elf64_half)0x18AD)
#define em_alpha ((elf64_half)0x9026)
#define em_cygnus_v850 ((elf64_half)0x9080)
#define em_cygnus_m32r ((elf64_half)0x9041)
#define em_s390_old ((elf64_half)0xA390)
#define em_cygnus_mn10300 ((elf64_half)0xBEEF)

const char *em_none_str = "none";
const char *em_m32_str = "m32";
const char *em_sparc_str = "sparc";
const char *em_386_str = "386";
const char *em_68k_str = "68k";
const char *em_88k_str = "88k";
const char *em_486_str = "486";
const char *em_860_str = "860";
const char *em_mips_str = "mips";
const char *em_mips_rs3_le_str = "mips_rs3_le";
const char *em_mips_rs4_be_str = "mips_rs4_be";
const char *em_parisc_str = "parisc";
const char *em_sparc32plus_str = "sparc32plus";
const char *em_ppc_str = "ppc";
const char *em_ppc64_str = "ppc64";
const char *em_spu_str = "spu";
const char *em_arm_str = "arm";
const char *em_sh_str = "sh";
const char *em_sparcv9_str = "sparcv9";
const char *em_h8_300_str = "h8_300";
const char *em_ia_64_str = "ia_64";
const char *em_x86_64_str = "x86_64";
const char *em_s390_str = "s390";
const char *em_cris_str = "cris";
const char *em_v850_str = "v850";
const char *em_m32r_str = "m32r";
const char *em_mn10300_str = "mn10300";
const char *em_openrisc_str = "openrisc";
const char *em_blackfin_str = "blackfin";
const char *em_altera_nios2_str = "altera_nios2";
const char *em_ti_c6000_str = "ti_c6000";
const char *em_aarch64_str = "aarch64";
const char *em_frv_str = "frv";
const char *em_avr32_str = "avr32";
const char *em_alpha_str = "alpha";
const char *em_cygnus_v850_str = "cygnus_v850";
const char *em_cygnus_m32r_str = "cygnus_m32r";
const char *em_s390_old_str = "s390_old";
const char *em_cygnus_mn10300_str = "cygnus_mn10300";

const char *
e_machine_to_str(elf64_half value);

/*
 * ELF File Header
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 3
 *
 * The file header is located at the beginning of the file, and is used to
 * locate the other parts of the file.
 */
struct elf64_ehdr
{
    unsigned char e_ident[ei_nident];
    elf64_half e_type;
    elf64_half e_machine;
    elf64_word e_version;
    elf64_addr e_entry;
    elf64_off e_phoff;
    elf64_off e_shoff;
    elf64_word e_flags;
    elf64_half e_ehsize;
    elf64_half e_phentsize;
    elf64_half e_phnum;
    elf64_half e_shentsize;
    elf64_half e_shnum;
    elf64_half e_shstrndx;
};

elf64_sword
elf_file_print_header(struct elf_file_t *ef);

/******************************************************************************/
/* ELF Section Header Table                                                   */
/******************************************************************************/

/*
 * ELF Section Type
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 7
 */
#define sht_null ((elf64_word)0)
#define sht_progbits ((elf64_word)1)
#define sht_symtab ((elf64_word)2)
#define sht_strtab ((elf64_word)3)
#define sht_rela ((elf64_word)4)
#define sht_hash ((elf64_word)5)
#define sht_dynamic ((elf64_word)6)
#define sht_note ((elf64_word)7)
#define sht_nobits ((elf64_word)8)
#define sht_rel ((elf64_word)9)
#define sht_shlib ((elf64_word)10)
#define sht_dynsym ((elf64_word)11)
#define sht_loos ((elf64_word)0x60000000)
#define sht_hios ((elf64_word)0x6FFFFFFF)
#define sht_loproc ((elf64_word)0x70000000)
#define sht_hiproc ((elf64_word)0x7FFFFFFF)

const char *sht_null_str = "Unused (sht_null)";
const char *sht_progbits_str = "Program data (sht_progbits)";
const char *sht_symtab_str = "Symbol table (sht_symtab)";
const char *sht_strtab_str = "String table (sht_strtab)";
const char *sht_rela_str = "Rela (sht_rela)";
const char *sht_hash_str = "Hash table (sht_hash)";
const char *sht_dynamic_str = "Dynamic linking table (sht_dynamic)";
const char *sht_note_str = "Note info (sht_note)";
const char *sht_nobits_str = "Uninitialized (sht_nobits)";
const char *sht_rel_str = "Rel (sht_rel)";
const char *sht_shlib_str = "Reserved (sht_shlib)";
const char *sht_dynsym_str = "Dynamic loader table (sht_dynsym)";
const char *sht_loos_str = "Process specific (sht_loos)";
const char *sht_hios_str = "Process specific (sht_hios)";
const char *sht_loproc_str = "Process specific (sht_loproc)";
const char *sht_hiproc_str = "Process specific (sht_hiproc)";

const char *
sh_type_to_str(elf64_word value);

/*
 * ELF Section Attributes
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 8
 */
#define shf_write ((elf64_xword)0x1)
#define shf_alloc ((elf64_xword)0x2)
#define shf_execinstr ((elf64_xword)0x4)
#define shf_maskos ((elf64_xword)0x0F000000)
#define shf_maskproc ((elf64_xword)0xF0000000)

/*
 * ELF sh_flags (writable) -> bool
 *
 * @param sh_flags sh_flags to convert to bool
 * @return ELF_TRUE if sh_flags contains shf_write, otherwise ELF_FALSE
 */
elf64_sword
sh_flags_is_writable(struct elf_shdr *shdr);

/*
 * ELF sh_flags (allocated) -> bool
 *
 * @param sh_flags sh_flags to convert to bool
 * @return ELF_TRUE if sh_flags contains shf_alloc, otherwise ELF_FALSE
 */
elf64_sword
sh_flags_is_allocated(struct elf_shdr *shdr);

/*
 * ELF sh_flags (executable) -> bool
 *
 * @param sh_flags sh_flags to convert to bool
 * @return ELF_TRUE if sh_flags contains shf_execinstr, otherwise ELF_FALSE
 */
elf64_sword
sh_flags_is_executable(struct elf_shdr *shdr);

/*
 * ELF Section Header Entry
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 6
 *
 * Sections contain all the information in an ELF file, except for the ELF
 * header, program header table, and section header table. Sections are
 * identified by an index into the section header table.
 */
struct elf_shdr
{
    elf64_word sh_name;
    elf64_word sh_type;
    elf64_xword sh_flags;
    elf64_addr sh_addr;
    elf64_off sh_offset;
    elf64_xword sh_size;
    elf64_word sh_link;
    elf64_word sh_info;
    elf64_xword sh_addralign;
    elf64_xword sh_entsize;
};

elf64_sword
elf_section_header(struct elf_file_t *ef,
                   elf64_word index,
                   struct elf_shdr **shdr);

elf64_sword
elf_print_section_header_table(struct elf_file_t *ef);

elf64_sword
elf_print_section_header(struct elf_file_t *ef,
                         struct elf_shdr *shdr);

/******************************************************************************/
/* String Table                                                               */
/******************************************************************************/

/*
 * String
 *
 * The problem with the ELF format is that strings are nothing more than a
 * NULL terminated character array, which doesn't help much in the presence
 * of a fuzzer. We define a string as a character array, plus a length,
 * which we can set to ensure safety (i.e. is NULL is not present, at least
 * we will not overrun the file).
 */
struct e_string
{
    const char *buf;
    elf64_sword len;
};

elf64_sword
elf_string_table_entry(struct elf_file_t *ef,
                       struct elf_shdr *strtab,
                       elf64_word offset,
                       struct e_string *str);


elf64_sword
elf_section_name_string(struct elf_file_t *ef,
                        struct elf_shdr *shdr,
                        struct e_string *str);

/******************************************************************************/
/* ELF Dynamic Symbol Table                                                   */
/******************************************************************************/

#define stb_local ((unsigned char)0)
#define stb_global ((unsigned char)1)
#define stb_weak ((unsigned char)2)
#define stb_loos ((unsigned char)10)
#define stb_hios ((unsigned char)12)
#define stb_loproc ((unsigned char)13)
#define stb_hiproc ((unsigned char)15)

const char *stb_local_str = "stb_local";
const char *stb_global_str = "stb_global";
const char *stb_weak_str = "stb_weak";
const char *stb_loos_str = "stb_loos";
const char *stb_hios_str = "stb_hios";
const char *stb_loproc_str = "stb_loproc";
const char *stb_hiproc_str = "stb_hiproc";

const char *
stb_to_str(elf64_word value);

#define stt_notype ((unsigned char)0)
#define stt_object ((unsigned char)1)
#define stt_func ((unsigned char)2)
#define stt_section ((unsigned char)3)
#define stt_file ((unsigned char)4)
#define stt_loos ((unsigned char)10)
#define stt_hios ((unsigned char)12)
#define stt_loproc ((unsigned char)13)
#define stt_hiproc ((unsigned char)15)

const char *stt_notype_str = "stt_notype";
const char *stt_object_str = "stt_object";
const char *stt_func_str = "stt_func";
const char *stt_section_str = "stt_section";
const char *stt_file_str = "stt_file";
const char *stt_loos_str = "stt_loos";
const char *stt_hios_str = "stt_hios";
const char *stt_loproc_str = "stt_loproc";
const char *stt_hiproc_str = "stt_hiproc";

const char *
stt_to_str(elf64_word value);

#define ELF_SYM_BIND(x) ((x) >> 4)
#define ELF_SYM_TYPE(x) ((x) & 0xF)

/*
 * ELF Symbol
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 9
 */
struct elf_sym
{
    elf64_word st_name;
    unsigned char st_info;
    unsigned char st_other;
    elf64_half st_shndx;
    elf64_addr st_value;
    elf64_xword st_size;
};

elf64_sword
elf_symbol_by_index(struct elf_file_t *ef,
                    elf64_word index,
                    struct elf_sym **sym);

elf64_sword
elf_symbol_by_name(struct elf_file_t *ef,
                   struct e_string *name,
                   struct elf_sym **sym);

elf64_sword
elf_symbol_by_name_global(struct elf_file_t *efl,
                          struct e_string *name,
                          struct elf_file_t **efr,
                          struct elf_sym **sym);

elf64_sword
elf_resolve_symbol(struct elf_file_t *ef,
                   struct e_string *name,
                   void **addr);

elf64_sword
elf_print_sym_table(struct elf_file_t *ef);

elf64_sword
elf_print_sym(struct elf_file_t *ef,
              struct elf_sym *sym);

/******************************************************************************/
/* ELF Relocations                                                            */
/******************************************************************************/

#define R_X86_64_64 ((elf64_xword)1)
#define R_X86_64_GLOB_DAT ((elf64_xword)6)
#define R_X86_64_JUMP_SLOT ((elf64_xword)7)
#define R_X86_64_RELATIVE ((elf64_xword)8)

const char *R_X86_64_64_STR = "R_X86_64_64";
const char *R_X86_64_GLOB_DAT_STR = "R_X86_64_GLOB_DAT";
const char *R_X86_64_JUMP_SLOT_STR = "R_X86_64_JUMP_SLOT";
const char *R_X86_64_RELATIVE_STR = "R_X86_64_RELATIVE";

const char *
rel_type_to_str(elf64_xword value);

struct elf_rel
{
    elf64_addr r_offset;
    elf64_xword r_info;
};

struct elf_rela
{
    elf64_addr r_offset;
    elf64_xword r_info;
    elf64_sxword r_addend;
};

#define ELF_REL_SYM(i)  ((i) >> 32)
#define ELF_REL_TYPE(i) ((i) & 0xFFFFFFFFL)

elf64_sword
elf_relocate_symbol(struct elf_file_t *ef,
                    struct elf_rel *rel);

elf64_sword
elf_relocate_symbol_addend(struct elf_file_t *ef,
                           struct elf_rela *rela);

elf64_sword
elf_relocate_symbols(struct elf_file_t *ef);

elf64_sword
elf_print_relocation(struct elf_rel *rel);

elf64_sword
elf_print_relocation_addend(struct elf_rela *rela);

elf64_sword
elf_print_relocations(struct elf_file_t *ef);

/******************************************************************************/
/* ELF Program Header                                                         */
/******************************************************************************/

/*
 * ELF Section Attributes
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 12
 */
#define pt_null ((elf64_word)0)
#define pt_load ((elf64_word)1)
#define pt_dynamic ((elf64_word)2)
#define pt_interp ((elf64_word)3)
#define pt_note ((elf64_word)4)
#define pt_shlib ((elf64_word)5)
#define pt_phdr ((elf64_word)6)
#define pt_loos ((elf64_word)0x60000000)
#define pt_hios ((elf64_word)0x6FFFFFFF)
#define pt_loproc ((elf64_word)0x70000000)
#define pt_hiproc ((elf64_word)0x7FFFFFFF)

const char *pt_null_str = "Unused entry (pt_null)";
const char *pt_load_str = "Loadable segment (pt_load)";
const char *pt_dynamic_str = "Dynamic linking tables (pt_dynamic)";
const char *pt_interp_str = "Program interpreter path name (pt_interp)";
const char *pt_note_str = "Note sections (pt_note)";
const char *pt_shlib_str = "Reserved (pt_shlib)";
const char *pt_phdr_str = "Program header table (pt_phdr)";
const char *pt_loos_str = "Environment specific (pt_loos)";
const char *pt_hios_str = "Environment specific (pt_hios)";
const char *pt_loproc_str = "Processor specific (pt_loproc)";
const char *pt_hiproc_str = "Processor specific (pt_hiproc)";

const char *
p_type_to_str(elf64_word value);

/*
 * ELF Section Attributes
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 13
 */
#define pf_x ((elf64_xword)0x1)
#define pf_w ((elf64_xword)0x2)
#define pf_r ((elf64_xword)0x4)
#define pf_maskos ((elf64_xword)0x00FF0000)
#define pf_maskproc ((elf64_xword)0xFF000000)

/*
 * ELF p_flags (executable) -> bool
 *
 * @param p_flags p_flags to convert to bool
 * @return ELF_TRUE if p_flags contains pf_x, otherwise ELF_FALSE
 */
elf64_sword
p_flags_is_executable(struct elf_phdr *phdr);

/*
 * ELF p_flags (writable) -> bool
 *
 * @param p_flags p_flags to convert to bool
 * @return ELF_TRUE if p_flags contains pf_w, otherwise ELF_FALSE
 */
elf64_sword
p_flags_is_writable(struct elf_phdr *phdr);

/*
 * ELF p_flags (readable) -> bool
 *
 * @param p_flags p_flags to convert to bool
 * @return ELF_TRUE if p_flags contains pf_r, otherwise ELF_FALSE
 */
elf64_sword
p_flags_is_readable(struct elf_phdr *phdr);

/*
 * ELF Program Header Entry
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 12
 *
 * In executable and shared object files, sections are grouped into segments for
 * loading. The program header table contains a list of entries describing
 * each segment.
 */
struct elf_phdr
{
    elf64_word p_type;
    elf64_word p_flags;
    elf64_off p_offset;
    elf64_addr p_vaddr;
    elf64_addr p_paddr;
    elf64_xword p_filesz;
    elf64_xword p_memsz;
    elf64_xword p_align;
};

elf64_sword
elf_program_header(struct elf_file_t *ef,
                   elf64_word index,
                   struct elf_phdr **phdr);

elf64_sxword
elf_total_exec_size(struct elf_file_t *ef);

elf64_sword
elf_load_segments(struct elf_file_t *ef);

elf64_sword
elf_load_segment(struct elf_file_t *ef,
                 struct elf_phdr *phdr);

elf64_sword
elf_print_program_header_table(struct elf_file_t *ef);

elf64_sword
elf_print_program_header(struct elf_file_t *ef,
                         struct elf_phdr *phdr);


#ifdef __cplusplus
}
#endif

#pragma pack(pop)
#endif
