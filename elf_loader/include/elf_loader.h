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

const elf64_sword ELF_TRUE = 1;
const elf64_sword ELF_FALSE = 0;

/******************************************************************************/
/* ELF Error Codes                                                            */
/******************************************************************************/

/*
 * ELF error codes
 *
 * The following define the different error codes that this library might
 * provide given bad input.
 */
const elf64_sword ELF_SUCCESS = 0;
const elf64_sword ELF_ERROR_INVALID_ARG = -1;
const elf64_sword ELF_ERROR_INVALID_FILE = -2;
const elf64_sword ELF_ERROR_INVALID_INDEX = -3;
const elf64_sword ELF_ERROR_INVALID_OFFSET = -4;
const elf64_sword ELF_ERROR_INVALID_STRING = -5;
const elf64_sword ELF_ERROR_INVALID_EI_MAG0 = -101;
const elf64_sword ELF_ERROR_INVALID_EI_MAG1 = -102;
const elf64_sword ELF_ERROR_INVALID_EI_MAG2 = -103;
const elf64_sword ELF_ERROR_INVALID_EI_MAG3 = -104;
const elf64_sword ELF_ERROR_INVALID_EI_CLASS = -105;
const elf64_sword ELF_ERROR_INVALID_EI_DATA = -106;
const elf64_sword ELF_ERROR_INVALID_EI_VERSION = -107;
const elf64_sword ELF_ERROR_INVALID_EI_OSABI = -108;
const elf64_sword ELF_ERROR_INVALID_EI_ABIVERSION = -109;
const elf64_sword ELF_ERROR_INVALID_E_TYPE = -110;
const elf64_sword ELF_ERROR_INVALID_E_MACHINE = -111;
const elf64_sword ELF_ERROR_INVALID_E_ENTRY = -112;
const elf64_sword ELF_ERROR_INVALID_E_PHOFF = -113;
const elf64_sword ELF_ERROR_INVALID_E_SHOFF = -114;
const elf64_sword ELF_ERROR_INVALID_E_FLAGS = -115;
const elf64_sword ELF_ERROR_INVALID_E_EHSIZE = -116;
const elf64_sword ELF_ERROR_INVALID_E_PHENTSIZE = -117;
const elf64_sword ELF_ERROR_INVALID_E_PHNUM = -118;
const elf64_sword ELF_ERROR_INVALID_E_SHENTSIZE = -119;
const elf64_sword ELF_ERROR_INVALID_E_SHNUM = -120;
const elf64_sword ELF_ERROR_INVALID_E_SHSTRNDX = -121;
const elf64_sword ELF_ERROR_INVALID_PHT = -122;
const elf64_sword ELF_ERROR_INVALID_SHT = -123;
const elf64_sword ELF_ERROR_INVALID_SH_NAME = -200;
const elf64_sword ELF_ERROR_INVALID_SH_TYPE = -201;
const elf64_sword ELF_ERROR_INVALID_SH_FLAGS = -202;
const elf64_sword ELF_ERROR_INVALID_SH_ADDR = -203;
const elf64_sword ELF_ERROR_INVALID_SH_OFFSET = -204;
const elf64_sword ELF_ERROR_INVALID_SH_SIZE = -205;
const elf64_sword ELF_ERROR_INVALID_SH_LINK = -206;
const elf64_sword ELF_ERROR_INVALID_SH_INFO = -207;
const elf64_sword ELF_ERROR_INVALID_SH_ADDRALIGN = -208;
const elf64_sword ELF_ERROR_INVALID_SH_ENTSIZE = -209;
const elf64_sword ELF_ERROR_INVALID_PH_TYPE = -300;
const elf64_sword ELF_ERROR_INVALID_PH_FLAGS = -301;
const elf64_sword ELF_ERROR_INVALID_PH_OFFSET = -302;
const elf64_sword ELF_ERROR_INVALID_PH_VADDR = -303;
const elf64_sword ELF_ERROR_INVALID_PH_PADDR = -304;
const elf64_sword ELF_ERROR_INVALID_PH_FILESZ = -305;
const elf64_sword ELF_ERROR_INVALID_PH_MEMSZ = -306;
const elf64_sword ELF_ERROR_INVALID_PH_ALIGN = -307;
const elf64_sword ELF_ERROR_INVALID_STRING_TABLE = -400;
const elf64_sword ELF_ERROR_NO_SUCH_SYMBOL = -500;
const elf64_sword ELF_ERROR_SYMBOL_UNDEFINED = -501;
const elf64_sword ELF_ERROR_LOADER_FULL = -600;
const elf64_sword ELF_ERROR_INVALID_LOADER = -601;
const elf64_sword ELF_ERROR_INVALID_RELOCATION_TYPE = -701;


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

/*
 * ELF error
 *
 * Returns a human reabable form of an ELF error
 *
 * @param error the return code from an ELF function
 * @return resulting string
 */
const char *
elf_error(elf64_sword error);

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
const elf64_sword ei_mag0 = 0;
const elf64_sword ei_mag1 = 1;
const elf64_sword ei_mag2 = 2;
const elf64_sword ei_mag3 = 3;
const elf64_sword ei_class = 4;
const elf64_sword ei_data = 5;
const elf64_sword ei_version = 6;
const elf64_sword ei_osabi = 7;
const elf64_sword ei_abiversion = 8;
const elf64_sword ei_pad = 9;
const elf64_sword ei_nident = 16;

/*
 * ELF Class Types
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 5
 */
const unsigned char elfclass32 = 1;
const unsigned char elfclass64 = 2;

const char *elfclass32_str = "ELF32 (elfclass32)";
const char *elfclass64_str = "ELF64 (elfclass64)";

/*
 * ELF ei_class -> char *
 *
 * Returns a human reabable form of ei_class
 *
 * @param ei_class ei_class to convert to string
 * @return resulting string
 */
const char *
ei_class_to_str(unsigned char ei_class);

/*
 * ELF Data Types
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 5
 */
const unsigned char elfdata2lsb = 1;
const unsigned char elfdata2msb = 2;

const char *elfdata2lsb_str = "2's complement, little endian (elfdata2lsb)";
const char *elfdata2msb_str = "2's complement, big endian (elfdata2msb)";

/*
 * ELF ei_data -> char *
 *
 * Returns a human reabable form of ei_data
 *
 * @param ei_data ei_data to convert to string
 * @return resulting string
 */
const char *
ei_data_to_str(unsigned char ei_data);

/*
 * ELF Version
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 4
 */
const unsigned char ev_current = 1;
const char *ev_current_str = "1 (ev_current)";

/*
 * ELF ei_version / e_version -> char *
 *
 * Returns a human reabable form of ei_version and e_version
 *
 * @param version version to convert to string
 * @return resulting string
 */
const char *
version_to_str(unsigned char version);

/*
 * ELF OS / ABI Types
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 5
 */
const unsigned char elfosabi_sysv = 0;
const unsigned char elfosabi_hpux = 1;
const unsigned char elfosabi_standalone = 255;

const char *elfosabi_sysv_str = "System V ABI (elfosabi_sysv)";
const char *elfosabi_hpux_str = "HP-UX operating system (elfosabi_hpux)";
const char *elfosabi_standalone_str = "Standalone (elfosabi_standalone)";

/*
 * ELF ei_osabi -> char *
 *
 * Returns a human reabable form of ei_osabi
 *
 * @param ei_osabi ei_osabi to convert to string
 * @return resulting string
 */
const char *
ei_osabi_to_str(unsigned char ei_osabi);

/*
 * ELF Types
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 5
 */
const elf64_half et_none = 0;
const elf64_half et_rel = 1;
const elf64_half et_exec = 2;
const elf64_half et_dyn = 3;
const elf64_half et_core = 4;
const elf64_half et_loos = 0xFE00;
const elf64_half et_hios = 0xFEFF;
const elf64_half et_loproc = 0xFF00;
const elf64_half et_hiproc = 0xFFFF;

const char *et_none_str = "No file type (et_none)";
const char *et_rel_str = "Relocatable object file (et_rel)";
const char *et_exec_str = "Executable file (et_exec)";
const char *et_dyn_str = "Shared object file (et_dyn)";
const char *et_core_str = "Core file (et_core)";
const char *et_loos_str = "Environment-specific use (et_loos)";
const char *et_hios_str = "Environment-specific use (et_hios)";
const char *et_loproc_str = "Processor-specific use (et_loproc)";
const char *et_hiproc_str = "Processor-specific use (et_hiproc)";

/*
 * ELF e_type -> char *
 *
 * Returns a human reabable form of e_type
 *
 * @param e_type e_type to convert to string
 * @return resulting string
 */
const char *
e_type_to_str(elf64_half e_type);

/*
 * ELF Machine Codes
 *
 * The following is defined in the Linux kernel sources:
 * linux/include/uapi/linux/elf-em.h
 */
const elf64_half em_none = 0;
const elf64_half em_m32 = 1;
const elf64_half em_sparc = 2;
const elf64_half em_386 = 3;
const elf64_half em_68k = 4;
const elf64_half em_88k = 5;
const elf64_half em_486 = 6;
const elf64_half em_860 = 7;
const elf64_half em_mips = 8;
const elf64_half em_mips_rs3_le = 10;
const elf64_half em_mips_rs4_be = 11;
const elf64_half em_parisc = 15;
const elf64_half em_sparc32plus = 18;
const elf64_half em_ppc = 20;
const elf64_half em_ppc64 = 21;
const elf64_half em_spu = 23;
const elf64_half em_arm = 40;
const elf64_half em_sh = 42;
const elf64_half em_sparcv9 = 43;
const elf64_half em_h8_300 = 46;
const elf64_half em_ia_64 = 50;
const elf64_half em_x86_64 = 62;
const elf64_half em_s390 = 22;
const elf64_half em_cris = 76;
const elf64_half em_v850 = 87;
const elf64_half em_m32r = 88;
const elf64_half em_mn10300 = 89;
const elf64_half em_openrisc = 92;
const elf64_half em_blackfin = 106;
const elf64_half em_altera_nios2 = 113;
const elf64_half em_ti_c6000 = 140;
const elf64_half em_aarch64 = 183;
const elf64_half em_frv = 0x5441;
const elf64_half em_avr32 = 0x18AD;
const elf64_half em_alpha = 0x9026;
const elf64_half em_cygnus_v850 = 0x9080;
const elf64_half em_cygnus_m32r = 0x9041;
const elf64_half em_s390_old = 0xA390;
const elf64_half em_cygnus_mn10300 = 0xBEEF;

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

/*
 * ELF e_machine -> char *
 *
 * Returns a human reabable form of e_machine
 *
 * @param e_machine e_machine to convert to string
 * @return resulting string
 */
const char *
e_machine_to_str(elf64_half e_machine);

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
const elf64_word sht_null = 0;
const elf64_word sht_progbits = 1;
const elf64_word sht_symtab = 2;
const elf64_word sht_strtab = 3;
const elf64_word sht_rela = 4;
const elf64_word sht_hash = 5;
const elf64_word sht_dynamic = 6;
const elf64_word sht_note = 7;
const elf64_word sht_nobits = 8;
const elf64_word sht_rel = 9;
const elf64_word sht_shlib = 10;
const elf64_word sht_dynsym = 11;
const elf64_word sht_loos = 0x60000000;
const elf64_word sht_hios = 0x6FFFFFFF;
const elf64_word sht_loproc = 0x70000000;
const elf64_word sht_hiproc = 0x7FFFFFFF;

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

/*
 * ELF sh_type -> char *
 *
 * Returns a human reabable form of sh_type
 *
 * @param sh_type sh_type to convert to string
 * @return resulting string
 */
const char *
sh_type_to_str(elf64_word sh_type);

/*
 * ELF Section Attributes
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 8
 */
const elf64_xword shf_write = 0x1;
const elf64_xword shf_alloc = 0x2;
const elf64_xword shf_execinstr = 0x4;
const elf64_xword shf_maskos = 0x0F000000;
const elf64_xword shf_maskproc = 0xF0000000;

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

const unsigned char stb_local = 0;
const unsigned char stb_global = 1;
const unsigned char stb_weak = 2;
const unsigned char stb_loos = 10;
const unsigned char stb_hios = 12;
const unsigned char stb_loproc = 13;
const unsigned char stb_hiproc = 15;

const char *stb_local_str = "stb_local";
const char *stb_global_str = "stb_global";
const char *stb_weak_str = "stb_weak";
const char *stb_loos_str = "stb_loos";
const char *stb_hios_str = "stb_hios";
const char *stb_loproc_str = "stb_loproc";
const char *stb_hiproc_str = "stb_hiproc";

/*
 * ELF stb -> char *
 *
 * Returns a human reabable form of st_info (bind)
 *
 * @param st_info st_info to convert to string
 * @return resulting string
 */
const char *
stb_to_str(elf64_word st_info);

const unsigned char stt_notype = 0;
const unsigned char stt_object = 1;
const unsigned char stt_func = 2;
const unsigned char stt_section = 3;
const unsigned char stt_file = 4;
const unsigned char stt_loos = 10;
const unsigned char stt_hios = 12;
const unsigned char stt_loproc = 13;
const unsigned char stt_hiproc = 15;

const char *stt_notype_str = "stt_notype";
const char *stt_object_str = "stt_object";
const char *stt_func_str = "stt_func";
const char *stt_section_str = "stt_section";
const char *stt_file_str = "stt_file";
const char *stt_loos_str = "stt_loos";
const char *stt_hios_str = "stt_hios";
const char *stt_loproc_str = "stt_loproc";
const char *stt_hiproc_str = "stt_hiproc";

/*
 * ELF stt -> char *
 *
 * Returns a human reabable form of st_info (type)
 *
 * @param st_info st_info to convert to string
 * @return resulting string
 */
const char *
stt_to_str(elf64_word st_info);

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

const elf64_xword R_X86_64_64 = 1;
const elf64_xword R_X86_64_GLOB_DAT = 6;
const elf64_xword R_X86_64_JUMP_SLOT = 7;
const elf64_xword R_X86_64_RELATIVE = 8;

const char *R_X86_64_64_STR = "R_X86_64_64";
const char *R_X86_64_GLOB_DAT_STR = "R_X86_64_GLOB_DAT";
const char *R_X86_64_JUMP_SLOT_STR = "R_X86_64_JUMP_SLOT";
const char *R_X86_64_RELATIVE_STR = "R_X86_64_RELATIVE";

/*
 * ELF r_info (type) -> char *
 *
 * Returns a human reabable form of r_info (type)
 *
 * @param r_info r_info to convert to string
 * @return resulting string
 */
const char *
rel_type_to_str(elf64_xword r_info);

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
const elf64_word pt_null = 0;
const elf64_word pt_load = 1;
const elf64_word pt_dynamic = 2;
const elf64_word pt_interp = 3;
const elf64_word pt_note = 4;
const elf64_word pt_shlib = 5;
const elf64_word pt_phdr = 6;
const elf64_word pt_loos = 0x60000000;
const elf64_word pt_hios = 0x6FFFFFFF;
const elf64_word pt_loproc = 0x70000000;
const elf64_word pt_hiproc = 0x7FFFFFFF;

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

/*
 * ELF p_type -> char *
 *
 * Returns a human reabable form of p_type
 *
 * @param p_type p_type to convert to string
 * @return resulting string
 */
const char *
p_type_to_str(elf64_word p_type);

/*
 * ELF Section Attributes
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 13
 */
const elf64_xword pf_x = 0x1;
const elf64_xword pf_w = 0x2;
const elf64_xword pf_r = 0x4;
const elf64_xword pf_maskos = 0x00FF0000;
const elf64_xword pf_maskproc = 0xFF000000;

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
