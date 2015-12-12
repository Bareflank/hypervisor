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

#ifndef BFELF_LOADER_H
#define BFELF_LOADER_H

#ifdef KERNEL
#include <linux/types.h>
#else
#include <inttypes.h>
#endif

#pragma pack(push, 1)

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/
/* ELF Defines                                                                */
/******************************************************************************/

#ifndef BFELF_MAX_MODULES
#define BFELF_MAX_MODULES 25
#endif

#ifndef BFELF_MAX_RELTAB
#define BFELF_MAX_RELTAB 3
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

typedef uint64_t bfelf64_addr;
typedef uint64_t bfelf64_off;
typedef uint16_t bfelf64_half;
typedef uint32_t bfelf64_word;
typedef int32_t bfelf64_sword;
typedef uint64_t bfelf64_xword;
typedef int64_t bfelf64_sxword;

#define BFELF_TRUE ((bfelf64_sword)1)
#define BFELF_FALSE ((bfelf64_sword)0)

/******************************************************************************/
/* ELF Error Codes                                                            */
/******************************************************************************/

/*
 * ELF error codes
 *
 * The following define the different error codes that this library might
 * provide given bad input.
 */
#define BFELF_SUCCESS ((bfelf64_sword)0)
#define BFELF_ERROR_INVALID_ARG ((bfelf64_sword)-1)
#define BFELF_ERROR_INVALID_FILE ((bfelf64_sword)-2)
#define BFELF_ERROR_INVALID_INDEX ((bfelf64_sword)-3)
#define BFELF_ERROR_INVALID_OFFSET ((bfelf64_sword)-4)
#define BFELF_ERROR_INVALID_STRING ((bfelf64_sword)-5)
#define BFELF_ERROR_INVALID_EI_MAG0 ((bfelf64_sword)-101)
#define BFELF_ERROR_INVALID_EI_MAG1 ((bfelf64_sword)-102)
#define BFELF_ERROR_INVALID_EI_MAG2 ((bfelf64_sword)-103)
#define BFELF_ERROR_INVALID_EI_MAG3 ((bfelf64_sword)-104)
#define BFELF_ERROR_INVALID_EI_CLASS ((bfelf64_sword)-105)
#define BFELF_ERROR_INVALID_EI_DATA ((bfelf64_sword)-106)
#define BFELF_ERROR_INVALID_EI_VERSION ((bfelf64_sword)-107)
#define BFELF_ERROR_INVALID_EI_OSABI ((bfelf64_sword)-108)
#define BFELF_ERROR_INVALID_EI_ABIVERSION ((bfelf64_sword)-109)
#define BFELF_ERROR_INVALID_E_TYPE ((bfelf64_sword)-110)
#define BFELF_ERROR_INVALID_E_MACHINE ((bfelf64_sword)-111)
#define BFELF_ERROR_INVALID_E_ENTRY ((bfelf64_sword)-112)
#define BFELF_ERROR_INVALID_E_PHOFF ((bfelf64_sword)-113)
#define BFELF_ERROR_INVALID_E_SHOFF ((bfelf64_sword)-114)
#define BFELF_ERROR_INVALID_E_FLAGS ((bfelf64_sword)-115)
#define BFELF_ERROR_INVALID_E_EHSIZE ((bfelf64_sword)-116)
#define BFELF_ERROR_INVALID_E_PHENTSIZE ((bfelf64_sword)-117)
#define BFELF_ERROR_INVALID_E_PHNUM ((bfelf64_sword)-118)
#define BFELF_ERROR_INVALID_E_SHENTSIZE ((bfelf64_sword)-119)
#define BFELF_ERROR_INVALID_E_SHNUM ((bfelf64_sword)-120)
#define BFELF_ERROR_INVALID_E_SHSTRNDX ((bfelf64_sword)-121)
#define BFELF_ERROR_INVALID_PHT ((bfelf64_sword)-122)
#define BFELF_ERROR_INVALID_SHT ((bfelf64_sword)-123)
#define BFELF_ERROR_INVALID_SH_NAME ((bfelf64_sword)-200)
#define BFELF_ERROR_INVALID_SH_TYPE ((bfelf64_sword)-201)
#define BFELF_ERROR_INVALID_SH_FLAGS ((bfelf64_sword)-202)
#define BFELF_ERROR_INVALID_SH_ADDR ((bfelf64_sword)-203)
#define BFELF_ERROR_INVALID_SH_OFFSET ((bfelf64_sword)-204)
#define BFELF_ERROR_INVALID_SH_SIZE ((bfelf64_sword)-205)
#define BFELF_ERROR_INVALID_SH_LINK ((bfelf64_sword)-206)
#define BFELF_ERROR_INVALID_SH_INFO ((bfelf64_sword)-207)
#define BFELF_ERROR_INVALID_SH_ADDRALIGN ((bfelf64_sword)-208)
#define BFELF_ERROR_INVALID_SH_ENTSIZE ((bfelf64_sword)-209)
#define BFELF_ERROR_INVALID_PH_TYPE ((bfelf64_sword)-300)
#define BFELF_ERROR_INVALID_PH_FLAGS ((bfelf64_sword)-301)
#define BFELF_ERROR_INVALID_PH_OFFSET ((bfelf64_sword)-302)
#define BFELF_ERROR_INVALID_PH_VADDR ((bfelf64_sword)-303)
#define BFELF_ERROR_INVALID_PH_PADDR ((bfelf64_sword)-304)
#define BFELF_ERROR_INVALID_PH_FILESZ ((bfelf64_sword)-305)
#define BFELF_ERROR_INVALID_PH_MEMSZ ((bfelf64_sword)-306)
#define BFELF_ERROR_INVALID_PH_ALIGN ((bfelf64_sword)-307)
#define BFELF_ERROR_INVALID_STRING_TABLE ((bfelf64_sword)-400)
#define BFELF_ERROR_NO_SUCH_SYMBOL ((bfelf64_sword)-500)
#define BFELF_ERROR_SYMBOL_UNDEFINED ((bfelf64_sword)-501)
#define BFELF_ERROR_LOADER_FULL ((bfelf64_sword)-600)
#define BFELF_ERROR_INVALID_LOADER ((bfelf64_sword)-601)
#define BFELF_ERROR_INVALID_RELOCATION_TYPE ((bfelf64_sword)-701)

/**
 * Convert ELF error -> const char *
 *
 * @param value error code to convert
 * @return const char * version of error code
 */
const char *
bfelf_error(bfelf64_sword value);

/******************************************************************************/
/* ELF File                                                                   */
/******************************************************************************/

struct bfelf_sym;
struct bfelf_rel;
struct bfelf_shdr;
struct bfelf64_ehdr;

/*
 * Relocation Table
 *
 * The following is used by this API to store information about a symbol
 * table.
 */
struct bfreltab_t
{
    bfelf64_sword num;
    struct bfelf_rel *tab;
};

struct bfrelatab_t
{
    bfelf64_sword num;
    struct bfelf_rela *tab;
};

/*
 * ELF File
 *
 * The following is used by this API to store information about the ELF file
 * being used.
 */
struct bfelf_file_t
{
    char *file;
    char *exec;
    bfelf64_sword fsize;
    bfelf64_sword esize;

    struct bfelf64_ehdr *ehdr;
    struct bfelf_shdr *shdrtab;
    struct bfelf_phdr *phdrtab;

    struct bfelf_shdr *dynsym;
    struct bfelf_shdr *strtab;
    struct bfelf_shdr *shstrtab;

    bfelf64_sword symnum;
    struct bfelf_sym *symtab;

    bfelf64_sword efnum;
    struct bfelf_file_t *eftab[BFELF_MAX_MODULES];

    bfelf64_sword num_rel;
    struct bfreltab_t bfreltab[BFELF_MAX_RELTAB];

    bfelf64_sword num_rela;
    struct bfrelatab_t bfrelatab[BFELF_MAX_RELTAB];

    bfelf64_sword valid;
};

/**
 * Initialize an ELF file
 *
 * This function initializes an ELF file structure given the file's contents
 * in memory. The resulting structure will be used by all of the other
 * functions.
 *
 * @param file a character buffer containing the contents of the ELF file to
 *     be loaded.
 * @param fsize the size of the character buffer
 * @param ef the ELF file structure to initialize.
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword
bfelf_file_init(char *file, bfelf64_sword fsize, struct bfelf_file_t *ef);

/**
 * Load ELF file
 *
 * Once an ELF file has been initialized, use bfelf_total_exec_size to
 * get the amount of RAM that is needed to load the ELF file into memory.
 * Using this information, allocate Read, Write, Exectuable memory for the
 * ELF file, that is used by this function. This function will actually load
 * the ELF file into the allocated RAM.
 *
 * @param ef the ELF file
 * @param exec a character buffer to load the ELF file into
 * @param esize the size of the character buffer
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword
bfelf_file_load(struct bfelf_file_t *ef, char *exec, bfelf64_sword esize);

/******************************************************************************/
/* ELF Loader                                                                 */
/******************************************************************************/

struct bfelf_loader_t
{
    bfelf64_sword num;
    struct bfelf_file_t *efs[BFELF_MAX_MODULES];
};

/**
 * Initialize ELF Loader
 *
 * The ELF loader is responsible for collecting all of the ELF files that
 * have been loaded, and relocates them in memory. If more then one library
 * is to be loaded, the relocation operation requires all of the symbol tables
 * from all of the libraries to be available during relocation.
 *
 * @param loader the ELF loader to initialize
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword
bfelf_loader_init(struct bfelf_loader_t *loader);

/**
 * Add ELF file to an ELF loader
 *
 * Once an ELF loader has been initialized, use this function to add an
 * ELF file to the ELF loader
 *
 * @param loader the ELF loader
 * @param ef the ELF file to add
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword
bfelf_loader_add(struct bfelf_loader_t *loader, struct bfelf_file_t *ef);

/**
 * Relocate ELF Loader
 *
 * Relocates all of the ELF files that have been added to the ELF loader.
 * Once all of the ELF files have been relocated, it's safe to resolve
 * symbols for execution.
 *
 * @param loader the ELF loader
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword
bfelf_loader_relocate(struct bfelf_loader_t *loader);

/******************************************************************************/
/* ELF File Header                                                            */
/******************************************************************************/

/*
 * e_ident indexes
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 3
 */
#define bfei_mag0 ((bfelf64_sword)0)
#define bfei_mag1 ((bfelf64_sword)1)
#define bfei_mag2 ((bfelf64_sword)2)
#define bfei_mag3 ((bfelf64_sword)3)
#define bfei_class ((bfelf64_sword)4)
#define bfei_data ((bfelf64_sword)5)
#define bfei_version ((bfelf64_sword)6)
#define bfei_osabi ((bfelf64_sword)7)
#define bfei_abiversion ((bfelf64_sword)8)
#define bfei_pad ((bfelf64_sword)9)
#define bfei_nident ((bfelf64_sword)16)

/*
 * ELF Class Types
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 5
 */
#define bfelfclass32 ((unsigned char)1)
#define bfelfclass64 ((unsigned char)2)

/**
 * Convert ei_class -> const char *
 *
 * @param value ei_class to convert
 * @return const char * version of ei_class
 */
const char *
ei_class_to_str(unsigned char value);

/*
 * ELF Data Types
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 5
 */
#define bfelfdata2lsb ((unsigned char)1)
#define bfelfdata2msb ((unsigned char)2)

/**
 * Convert ei_data -> const char *
 *
 * @param value ei_data to convert
 * @return const char * version of ei_data
 */
const char *
ei_data_to_str(unsigned char value);

/*
 * ELF Version
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 4
 */
#define bfev_current ((unsigned char)1)

/**
 * Convert version -> const char *
 *
 * @param value version to convert
 * @return const char * version of version
 */
const char *
version_to_str(unsigned char value);

/*
 * ELF OS / ABI Types
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 5
 */
#define bfelfosabi_sysv ((unsigned char)0)
#define bfelfosabi_hpux ((unsigned char)1)
#define bfelfosabi_standalone ((unsigned char)255)

/**
 * Convert ei_osabi -> const char *
 *
 * @param value ei_osabi to convert
 * @return const char * version of ei_osabi
 */
const char *
ei_osabi_to_str(unsigned char value);

/*
 * ELF Types
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 5
 */
#define bfet_none ((bfelf64_half)0)
#define bfet_rel ((bfelf64_half)1)
#define bfet_exec ((bfelf64_half)2)
#define bfet_dyn ((bfelf64_half)3)
#define bfet_core ((bfelf64_half)4)
#define bfet_loos ((bfelf64_half)0xFE00)
#define bfet_hios ((bfelf64_half)0xFEFF)
#define bfet_loproc ((bfelf64_half)0xFF00)
#define bfet_hiproc ((bfelf64_half)0xFFFF)

/**
 * Convert e_type -> const char *
 *
 * @param value e_type to convert
 * @return const char * version of e_type
 */
const char *
e_type_to_str(bfelf64_half value);

/*
 * ELF Machine Codes
 *
 * The following is defined in the Linux kernel sources:
 * linux/include/uapi/linux/elf-em.h
 */
#define bfem_none ((bfelf64_half)0)
#define bfem_m32 ((bfelf64_half)1)
#define bfem_sparc ((bfelf64_half)2)
#define bfem_386 ((bfelf64_half)3)
#define bfem_68k ((bfelf64_half)4)
#define bfem_88k ((bfelf64_half)5)
#define bfem_486 ((bfelf64_half)6)
#define bfem_860 ((bfelf64_half)7)
#define bfem_mips ((bfelf64_half)8)
#define bfem_mips_rs3_le ((bfelf64_half)10)
#define bfem_mips_rs4_be ((bfelf64_half)11)
#define bfem_parisc ((bfelf64_half)15)
#define bfem_sparc32plus ((bfelf64_half)18)
#define bfem_ppc ((bfelf64_half)20)
#define bfem_ppc64 ((bfelf64_half)21)
#define bfem_spu ((bfelf64_half)23)
#define bfem_arm ((bfelf64_half)40)
#define bfem_sh ((bfelf64_half)42)
#define bfem_sparcv9 ((bfelf64_half)43)
#define bfem_h8_300 ((bfelf64_half)46)
#define bfem_ia_64 ((bfelf64_half)50)
#define bfem_x86_64 ((bfelf64_half)62)
#define bfem_s390 ((bfelf64_half)22)
#define bfem_cris ((bfelf64_half)76)
#define bfem_v850 ((bfelf64_half)87)
#define bfem_m32r ((bfelf64_half)88)
#define bfem_mn10300 ((bfelf64_half)89)
#define bfem_openrisc ((bfelf64_half)92)
#define bfem_blackfin ((bfelf64_half)106)
#define bfem_altera_nios2 ((bfelf64_half)113)
#define bfem_ti_c6000 ((bfelf64_half)140)
#define bfem_aarch64 ((bfelf64_half)183)
#define bfem_frv ((bfelf64_half)0x5441)
#define bfem_avr32 ((bfelf64_half)0x18AD)
#define bfem_alpha ((bfelf64_half)0x9026)
#define bfem_cygnus_v850 ((bfelf64_half)0x9080)
#define bfem_cygnus_m32r ((bfelf64_half)0x9041)
#define bfem_s390_old ((bfelf64_half)0xA390)
#define bfem_cygnus_mn10300 ((bfelf64_half)0xBEEF)

/**
 * Convert e_machine -> const char *
 *
 * @param value e_machine to convert
 * @return const char * version of e_machine
 */
const char *
e_machine_to_str(bfelf64_half value);

/*
 * ELF File Header
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 3
 *
 * The file header is located at the beginning of the file, and is used to
 * locate the other parts of the file.
 */
struct bfelf64_ehdr
{
    unsigned char e_ident[bfei_nident];
    bfelf64_half e_type;
    bfelf64_half e_machine;
    bfelf64_word e_version;
    bfelf64_addr e_entry;
    bfelf64_off e_phoff;
    bfelf64_off e_shoff;
    bfelf64_word e_flags;
    bfelf64_half e_ehsize;
    bfelf64_half e_phentsize;
    bfelf64_half e_phnum;
    bfelf64_half e_shentsize;
    bfelf64_half e_shnum;
    bfelf64_half e_shstrndx;
};

/**
 * Print ELF file header
 *
 * @param ef the ELF file
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword
bfelf_file_print_header(struct bfelf_file_t *ef);

/******************************************************************************/
/* ELF Section Header Table                                                   */
/******************************************************************************/

/*
 * ELF Section Type
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 7
 */
#define bfsht_null ((bfelf64_word)0)
#define bfsht_progbits ((bfelf64_word)1)
#define bfsht_symtab ((bfelf64_word)2)
#define bfsht_strtab ((bfelf64_word)3)
#define bfsht_rela ((bfelf64_word)4)
#define bfsht_hash ((bfelf64_word)5)
#define bfsht_dynamic ((bfelf64_word)6)
#define bfsht_note ((bfelf64_word)7)
#define bfsht_nobits ((bfelf64_word)8)
#define bfsht_rel ((bfelf64_word)9)
#define bfsht_shlib ((bfelf64_word)10)
#define bfsht_dynsym ((bfelf64_word)11)
#define bfsht_loos ((bfelf64_word)0x60000000)
#define bfsht_hios ((bfelf64_word)0x6FFFFFFF)
#define bfsht_loproc ((bfelf64_word)0x70000000)
#define bfsht_hiproc ((bfelf64_word)0x7FFFFFFF)

/**
 * Convert sh_type -> const char *
 *
 * @param value sh_type to convert
 * @return const char * version of sh_type
 */
const char *
sh_type_to_str(bfelf64_word value);

/*
 * ELF Section Attributes
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 8
 */
#define bfshf_write ((bfelf64_xword)0x1)
#define bfshf_alloc ((bfelf64_xword)0x2)
#define bfshf_execinstr ((bfelf64_xword)0x4)
#define bfshf_maskos ((bfelf64_xword)0x0F000000)
#define bfshf_maskproc ((bfelf64_xword)0xF0000000)

/**
 * Convert sh_flags (writable) -> bool
 *
 * @param shdr section header with sh_flags to convert
 * @return BFELF_TRUE if writable, BFELF_FALSE otherwise
 */
bfelf64_sword
sh_flags_is_writable(struct bfelf_shdr *shdr);

/**
 * Convert sh_flags (allocated) -> bool
 *
 * @param shdr section header with sh_flags to convert
 * @return BFELF_TRUE if allocated, BFELF_FALSE otherwise
 */
bfelf64_sword
sh_flags_is_allocated(struct bfelf_shdr *shdr);

/**
 * Convert sh_flags (executable) -> bool
 *
 * @param shdr section header with sh_flags to convert
 * @return BFELF_TRUE if executable, BFELF_FALSE otherwise
 */
bfelf64_sword
sh_flags_is_executable(struct bfelf_shdr *shdr);

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
struct bfelf_shdr
{
    bfelf64_word sh_name;
    bfelf64_word sh_type;
    bfelf64_xword sh_flags;
    bfelf64_addr sh_addr;
    bfelf64_off sh_offset;
    bfelf64_xword sh_size;
    bfelf64_word sh_link;
    bfelf64_word sh_info;
    bfelf64_xword sh_addralign;
    bfelf64_xword sh_entsize;
};

/**
 * Get ELF section header
 *
 * @param ef the ELF file
 * @param index the index of the section to get
 * @param shdr the section header to return
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword
bfelf_section_header(struct bfelf_file_t *ef,
                     bfelf64_word index,
                     struct bfelf_shdr **shdr);

/**
 * Print ELF section header table
 *
 * @param ef the ELF file
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword
bfelf_print_section_header_table(struct bfelf_file_t *ef);

/**
 * Print ELF section header
 *
 * @param ef the ELF file
 * @param shdr the section header to print
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword
bfelf_print_section_header(struct bfelf_file_t *ef,
                           struct bfelf_shdr *shdr);

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
struct e_string_t
{
    const char *buf;
    bfelf64_sword len;
};

/**
 * Get ELF string table entry
 *
 * In each ELF file there are multiple string tables. Usually there is at
 * least a string table for all of the section headers (e.g. .got, .hash,
 * .dynsym, etc...) and then there is a string table for all of the dynamic
 * symbol names (e.g. fun1, my_glob1, etc...). A string table is nothing more
 * than a collection of null terminated strings, back to back. This function
 * takes a string table, and an offset into the table, and returns a string.
 *
 * @param ef the ELF file
 * @param strtab the string table
 * @param offset the offset (in bytes) into the string table
 * @param str the string being returned
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword
bfelf_string_table_entry(struct bfelf_file_t *ef,
                         struct bfelf_shdr *strtab,
                         bfelf64_word offset,
                         struct e_string_t *str);


/**
 * Get ELF section name
 *
 * This is a helper function for getting a section name.
 *
 * @param ef the ELF file
 * @param shdr the section header to get the name for
 * @param str the string being returned
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword
bfelf_section_name_string(struct bfelf_file_t *ef,
                          struct bfelf_shdr *shdr,
                          struct e_string_t *str);

/******************************************************************************/
/* ELF Dynamic Symbol Table                                                   */
/******************************************************************************/

#define bfstb_local ((unsigned char)0)
#define bfstb_global ((unsigned char)1)
#define bfstb_weak ((unsigned char)2)
#define bfstb_loos ((unsigned char)10)
#define bfstb_hios ((unsigned char)12)
#define bfstb_loproc ((unsigned char)13)
#define bfstb_hiproc ((unsigned char)15)

/**
 * Convert stb -> const char *
 *
 * @param value stb to convert
 * @return const char * version of stb
 */
const char *
stb_to_str(bfelf64_word value);

#define bfstt_notype ((unsigned char)0)
#define bfstt_object ((unsigned char)1)
#define bfstt_func ((unsigned char)2)
#define bfstt_section ((unsigned char)3)
#define bfstt_file ((unsigned char)4)
#define bfstt_loos ((unsigned char)10)
#define bfstt_hios ((unsigned char)12)
#define bfstt_loproc ((unsigned char)13)
#define bfstt_hiproc ((unsigned char)15)

/**
 * Convert stt -> const char *
 *
 * @param value stt to convert
 * @return const char * version of stt
 */
const char *
stt_to_str(bfelf64_word value);

#define BFELF_SYM_BIND(x) ((x) >> 4)
#define BFELF_SYM_TYPE(x) ((x) & 0xF)

/*
 * ELF Symbol
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 9
 */
struct bfelf_sym
{
    bfelf64_word st_name;
    unsigned char st_info;
    unsigned char st_other;
    bfelf64_half st_shndx;
    bfelf64_addr st_value;
    bfelf64_xword st_size;
};

/**
 * Get Dynamic Symbol (by index)
 *
 * This function will get a symbol from the dynamic symbol table given an
 * index. Note that this function does _not_ attempt to locate the symbol if
 * it's value is 0.
 *
 * @param ef the ELF file
 * @param index index into the .dynsym section
 * @param sym the symbol being returned
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword
bfelf_symbol_by_index(struct bfelf_file_t *ef,
                      bfelf64_word index,
                      struct bfelf_sym **sym);

/**
 * Get Dynamic Symbol (by name)
 *
 * This function will get a symbol from the dynamic symbol table given a
 * name. Note that this function does _not_ attempt to locate the symbol if
 * it's value is 0.
 *
 * @param ef the ELF file
 * @param name name of the symbol in the .dynsym section to get
 * @param sym the symbol being returned
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword
bfelf_symbol_by_name(struct bfelf_file_t *ef,
                     struct e_string_t *name,
                     struct bfelf_sym **sym);

/**
 * Get Global Dynamic Symbol (by name)
 *
 * This function will get a symbol from the dynamic symbol table given a
 * name. If the symbol is not defined in the ELF file that was provided
 * (i.e. st_value == 0), this function will search all of the other ELF files
 * that were provided by an ELF loader to see if it can find the symbol that
 * is actually defined. If this function returns, BFELF_ERROR_NO_SUCH_SYMBOL
 * the symbol is not defined by any of the ELF files that were loaded. If
 * the symbol was located, this function not only returns the symbol, but it
 * also returns the ELF file that the symbol was located in (which might be
 * the ELF file that was provided, or it might be an ELF file provided to
 * an ELF loader).
 *
 * @param efl the ELF file
 * @param name name of the symbol in the .dynsym section to get
 * @param efr the resulting ELF file that the symbol was located in
 * @param sym the symbol being returned
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword
bfelf_symbol_by_name_global(struct bfelf_file_t *efl,
                            struct e_string_t *name,
                            struct bfelf_file_t **efr,
                            struct bfelf_sym **sym);

/**
 * Resvole Symbol
 *
 * This function will lookup a symbol by it's name, and return it's absolute
 * address. Before this function can be run, the following must be done:
 *
 * - Each ELF file must be created and initalized.
 * - Each ELF file must be loaded into memory
 * - An ELF loader much be created an initalized.
 * - Each ELF file must be added to the ELF loader
 * - The ELF loader must be relocated
 *
 * Once these steps are completed, this function can be used to lookup the
 * absolute address for any symbol. Note that this function will return
 * the absolute address of a symbol in a different ELF file that what is
 * provided. It will however take longer as it must perform a global search.
 * Therefore, it is advised that the search be done on the ELF file that is
 * likely to contain the symbol.
 *
 * @param ef the ELF file
 * @param name name of the symbol in the .dynsym section to get
 * @param addr the resulting absolute address
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword
bfelf_resolve_symbol(struct bfelf_file_t *ef,
                     struct e_string_t *name,
                     void **addr);

/**
 * Print dynamic symbol table
 *
 * @param ef the ELF file
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword
bfelf_print_sym_table(struct bfelf_file_t *ef);

/**
 * Print dynamic symbol
 *
 * @param ef the ELF file
 * @param sym the symbol to print
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword
bfelf_print_sym(struct bfelf_file_t *ef,
                struct bfelf_sym *sym);

/******************************************************************************/
/* ELF Relocations                                                            */
/******************************************************************************/

#define BFR_X86_64_64 ((bfelf64_xword)1)
#define BFR_X86_64_GLOB_DAT ((bfelf64_xword)6)
#define BFR_X86_64_JUMP_SLOT ((bfelf64_xword)7)
#define BFR_X86_64_RELATIVE ((bfelf64_xword)8)

/**
 * Convert r_info (type) -> const char *
 *
 * @param value r_info (type) to convert
 * @return const char * version of r_info (type)
 */
const char *
rel_type_to_str(bfelf64_xword value);

struct bfelf_rel
{
    bfelf64_addr r_offset;
    bfelf64_xword r_info;
};

struct bfelf_rela
{
    bfelf64_addr r_offset;
    bfelf64_xword r_info;
    bfelf64_sxword r_addend;
};

#define BFELF_REL_SYM(i)  ((i) >> 32)
#define BFELF_REL_TYPE(i) ((i) & 0xFFFFFFFFL)

/**
 * Relocate Symbol
 *
 * Given a relocation record (from a relocation table), this function
 * performs the actual relocation.
 *
 * @note for x86_64, the documentation states that *ptr = S for GLOB_DAT and
 *     JUMP_SLOT. S in the documentation is sym->st_value, which is missing
 *     the base address to make the address "absolute". Most of the
 *     implementations that I found include the base address, so I believe this
 *     documentation to be in error. I have included the spec and a reference
 *     implementation in case it is needed.
 *
 * http://www.x86-64.org/documentation_folder/abi.pdf
 * https://github.com/madd-games/glidix/blob/186e2f699c045440f96551fcf504833d6d81799e/src/interp.c
 *
 * @param ef the ELF file
 * @param rel the relocation record to relocate
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword
bfelf_relocate_symbol(struct bfelf_file_t *ef,
                      struct bfelf_rel *rel);

/**
 * Relocate Symbol (Addend)
 *
 * Given a relocation record (from a relocation table), this function
 * performs the actual relocation.
 *
 * @note for x86_64, the documentation states that *ptr = S for GLOB_DAT and
 *     JUMP_SLOT. S in the documentation is sym->st_value, which is missing
 *     the base address to make the address "absolute". Most of the
 *     implementations that I found include the base address, so I believe this
 *     documentation to be in error. I have included the spec and a reference
 *     implementation in case it is needed.
 *
 * http://www.x86-64.org/documentation_folder/abi.pdf
 * https://github.com/madd-games/glidix/blob/186e2f699c045440f96551fcf504833d6d81799e/src/interp.c
 *
 * @note The difference with this function is that it has an extra addend added
 * to the absolute address. This is only needed for a couple of types of
 * relocations, the big one being code like int x[2], *y = x + 1, which creates
 * a BFR_X86_64_64 style relocation.
 *
 * @param ef the ELF file
 * @param rela the relocation record to relocate
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword
bfelf_relocate_symbol_addend(struct bfelf_file_t *ef,
                             struct bfelf_rela *rela);

/**
 * Relocate Symbols
 *
 * This function goes through all of the relocation tables, and relocates
 * each record in each relocation table.
 *
 * @param ef the ELF file
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword
bfelf_relocate_symbols(struct bfelf_file_t *ef);

/**
 * Print Relocation
 *
 * @param rel the relocation record to print
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword
bfelf_print_relocation(struct bfelf_rel *rel);

/**
 * Print Relocation (Addend)
 *
 * @param rela the relocation record to print
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword
bfelf_print_relocation_addend(struct bfelf_rela *rela);

/**
 * Print Relocations
 *
 * @param ef the ELF file
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword
bfelf_print_relocations(struct bfelf_file_t *ef);

/******************************************************************************/
/* ELF Program Header                                                         */
/******************************************************************************/

/*
 * ELF Section Attributes
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 12
 */
#define bfpt_null ((bfelf64_word)0)
#define bfpt_load ((bfelf64_word)1)
#define bfpt_dynamic ((bfelf64_word)2)
#define bfpt_interp ((bfelf64_word)3)
#define bfpt_note ((bfelf64_word)4)
#define bfpt_shlib ((bfelf64_word)5)
#define bfpt_phdr ((bfelf64_word)6)
#define bfpt_loos ((bfelf64_word)0x60000000)
#define bfpt_hios ((bfelf64_word)0x6FFFFFFF)
#define bfpt_loproc ((bfelf64_word)0x70000000)
#define bfpt_hiproc ((bfelf64_word)0x7FFFFFFF)

/**
 * Convert p_type (type) -> const char *
 *
 * @param value p_type (type) to convert
 * @return const char * version of p_type (type)
 */
const char *
p_type_to_str(bfelf64_word value);

/*
 * ELF Section Attributes
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 13
 */
#define bfpf_x ((bfelf64_xword)0x1)
#define bfpf_w ((bfelf64_xword)0x2)
#define bfpf_r ((bfelf64_xword)0x4)
#define bfpf_maskos ((bfelf64_xword)0x00FF0000)
#define bfpf_maskproc ((bfelf64_xword)0xFF000000)

/**
 * Convert p_flags (executable) -> bool
 *
 * @param phdr program header containing p_flags to convert
 * @return BFELF_TRUE if executable, BFELF_FALSE otherwise
 */
bfelf64_sword
p_flags_is_executable(struct bfelf_phdr *phdr);

/**
 * Convert p_flags (writable) -> bool
 *
 * @param phdr program header containing p_flags to convert
 * @return BFELF_TRUE if writable, BFELF_FALSE otherwise
 */
bfelf64_sword
p_flags_is_writable(struct bfelf_phdr *phdr);

/**
 * Convert p_flags (readable) -> bool
 *
 * @param phdr program header containing p_flags to convert
 * @return BFELF_TRUE if readable, BFELF_FALSE otherwise
 */
bfelf64_sword
p_flags_is_readable(struct bfelf_phdr *phdr);

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
struct bfelf_phdr
{
    bfelf64_word p_type;
    bfelf64_word p_flags;
    bfelf64_off p_offset;
    bfelf64_addr p_vaddr;
    bfelf64_addr p_paddr;
    bfelf64_xword p_filesz;
    bfelf64_xword p_memsz;
    bfelf64_xword p_align;
};

/**
 * Get ELF program header
 *
 * @param ef the ELF file
 * @param index the index of the program header to get
 * @param phdr the program header to return
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword
bfelf_program_header(struct bfelf_file_t *ef,
                     bfelf64_word index,
                     struct bfelf_phdr **phdr);

/**
 * Get exec size
 *
 * If the ELF file is "x" bytes, the RAM that the ELF file needs to be
 * loaded into would be "y" >= "x". The reason for this is the RAM would at
 * least need to add .bss section (which is not included in the ELF file itself)
 * and it's likely that the ELF file is broken up into read/execute and
 * read/write program segments, which are aligned to a "max" page size
 * boundary. For example, with a x86_64 cross compiler, the max page size is
 * 2MB. Thus, all of the read / executable sections are mapped to the first
 * set of pages marked for RE. The read / write sections (like .data) are all
 * in the a RW segment that are page aligned to 2MB. For a small library, this
 * would mean that the RE section is 0->2MB, and the RW section is 2MB->End.
 *
 * This function returns the total amount of RAM that is needed to load he
 * ELF file into RAM. This includes all of the segments, and their offsets for
 * page alignment.
 *
 * @param ef the ELF file
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sxword
bfelf_total_exec_size(struct bfelf_file_t *ef);

/**
 * Load segments
 *
 * Loads the segments in the ELF file into RAM.
 *
 * @param ef the ELF file
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword
bfelf_load_segments(struct bfelf_file_t *ef);

/**
 * Load segment
 *
 * Loads a specific segment into RAM. Note that a segment is a collection of
 * sections (e.g. .data, .got, .text, etc...). Typically there are two, one
 * for read / execute, and one for read / write. They can also be larger than
 * the ELF file. For example, the RW segment likely contains a .bss which is
 * not included in the ELF file. The segment defines where this bss section
 * is located, and what it's size is.
 *
 * @param ef the ELF file
 * @param phdr the program header for the segment to load
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword
bfelf_load_segment(struct bfelf_file_t *ef,
                   struct bfelf_phdr *phdr);

/**
 * Print Program Header Table
 *
 * @param ef the ELF file
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword
bfelf_print_program_header_table(struct bfelf_file_t *ef);

/**
 * Print Program Header
 *
 * @param ef the ELF file
 * @param phdr the program header for the segment to print
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword
bfelf_print_program_header(struct bfelf_file_t *ef,
                           struct bfelf_phdr *phdr);


#ifdef __cplusplus
}
#endif

#pragma pack(pop)
#endif
