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

#include <crt.h>

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

#ifndef BFELF_MAX_RELATAB
#define BFELF_MAX_RELATAB 8
#endif

#ifndef BFELF_MAX_SEGMENTS
#define BFELF_MAX_SEGMENTS 4
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

/******************************************************************************/
/* ELF Error Codes                                                            */
/******************************************************************************/

#define BFELF_ERROR_START ((bfelf64_sword)-11000)

/*
 * ELF error codes
 *
 * The following define the different error codes that this library might
 * provide given bad input.
 */
#define BFELF_SUCCESS ((bfelf64_sword)0)
#define BFELF_ERROR_INVALID_ARG (BFELF_ERROR_START - (bfelf64_sword)1)
#define BFELF_ERROR_INVALID_FILE (BFELF_ERROR_START - (bfelf64_sword)2)
#define BFELF_ERROR_INVALID_INDEX (BFELF_ERROR_START - (bfelf64_sword)3)
#define BFELF_ERROR_INVALID_STRING (BFELF_ERROR_START - (bfelf64_sword)4)
#define BFELF_ERROR_INVALID_SIGNATURE (BFELF_ERROR_START - (bfelf64_sword)5)
#define BFELF_ERROR_UNSUPPORTED_FILE (BFELF_ERROR_START - (bfelf64_sword)6)
#define BFELF_ERROR_INVALID_SEGMENT (BFELF_ERROR_START - (bfelf64_sword)7)
#define BFELF_ERROR_INVALID_SECTION (BFELF_ERROR_START - (bfelf64_sword)8)
#define BFELF_ERROR_LOADER_FULL (BFELF_ERROR_START - (bfelf64_sword)9)
#define BFELF_ERROR_NO_SUCH_SYMBOL (BFELF_ERROR_START - (bfelf64_sword)10)
#define BFELF_ERROR_MISMATCH (BFELF_ERROR_START - (bfelf64_sword)11)
#define BFELF_ERROR_UNSUPPORTED_RELA (BFELF_ERROR_START - (bfelf64_sword)12)
#define BFELF_ERROR_OUT_OF_ORDER (BFELF_ERROR_START - (bfelf64_sword)13)

/**
 * Convert ELF error -> const char *
 *
 * @param value error code to convert
 * @return const char * version of error code
 */
const char *bfelf_error(bfelf64_sword value);

/******************************************************************************/
/* ELF File                                                                   */
/******************************************************************************/

struct bfelf_sym;
struct bfelf_rel;
struct bfelf_shdr;
struct bfelf64_ehdr;

/*
 * String
 *
 * The following defines an ELF string, which is a C style, null terminated
 * string, with it's expected length.
 *
 */
struct e_string_t
{
    const char *buf;
    bfelf64_sword len;
};

/*
 * Relocation Table
 *
 * The following is used by this API to store information about a symbol
 * table.
 */
struct relatab_t
{
    bfelf64_word num;
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
    uint64_t fsize;

    uint64_t num_loadable_segments;
    struct bfelf_phdr *loadable_segments[BFELF_MAX_SEGMENTS];

    struct bfelf64_ehdr *ehdr;
    struct bfelf_shdr *shdrtab;
    struct bfelf_phdr *phdrtab;

    struct bfelf_shdr *dynsym;
    struct bfelf_shdr *hashtab;
    struct bfelf_shdr *strtab;
    struct bfelf_shdr *shstrtab;

    bfelf64_word nbucket;
    bfelf64_word nchain;
    bfelf64_word *bucket;
    bfelf64_word *chain;

    bfelf64_word symnum;
    struct bfelf_sym *symtab;

    bfelf64_word num_rela;
    struct relatab_t relatab[BFELF_MAX_RELATAB];

    bfelf64_word relocated;
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
bfelf64_sword bfelf_file_init(char *file,
                              uint64_t fsize,
                              struct bfelf_file_t *ef);

/**
 * Get number of program segments
 *
 * Once an ELF file has been initialized, the next step is to load all of the
 * program segments into memory, relocate them, and then execute the entry
 * point. To assist this operation, this function returns the total number of
 * program segments.
 *
 * @param ef the ELF file
 * @return number of segments on success, negative on error
 */
bfelf64_sxword bfelf_file_num_segments(struct bfelf_file_t *ef);

/**
 * Get program segment
 *
 * Once you know how many program segments there are, you can use this
 * function to get each segment. This ELF library doesn't simplify the
 * program loading part, because how this inforamtion is used, greatly depends
 * on the scenario, and all of the information in the program header is needed
 * depending on how your loading the program.
 *
 * @note The segment has already been sanitized by the ELF library. Doing these
 * checks again would only be wasteful.
 *
 * @param ef the ELF file
 * @param index the segment index to get
 * @param phdr where to store the segment's program header
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword bfelf_file_get_segment(struct bfelf_file_t *ef,
                                     bfelf64_word index,
                                     struct bfelf_phdr **phdr);

/**
 * Resolve Symbol
 *
 * Once an ELF loader has had all of it's ELF files initalized and added,
 * use the relocate ELF loader to setup the ELF files such that they can
 * be executed. If the ELF file is relocated into memory that is accessable
 * via the ELF loader, the resolve symbol function can be used to get the
 * address of a specific symbol so that it can be executed.
 *
 * Note that this version takes a single ELF module instead of the
 * loader. The loader version will do a global lookup if it has to.
 *
 * @param ef the ELF file to get the symbol from
 * @param name the name of the symbol to resolve
 * @param addr the resulting address if the symbol is successfully resolved
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword bfelf_file_resolve_symbol(struct bfelf_file_t *ef,
                                        struct e_string_t *name,
                                        void **addr);

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

/*
 * ELF Data Types
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 5
 */
#define bfelfdata2lsb ((unsigned char)1)
#define bfelfdata2msb ((unsigned char)2)

/*
 * ELF Version
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 4
 */
#define bfev_current ((unsigned char)1)

/*
 * ELF OS / ABI Types
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 5
 */
#define bfelfosabi_sysv ((unsigned char)0)
#define bfelfosabi_hpux ((unsigned char)1)
#define bfelfosabi_standalone ((unsigned char)255)

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
#define bfshf_undocumneted ((bfelf64_xword)0x00000060)

#define bfshf_a (bfshf_alloc)
#define bfshf_wa (bfshf_write | bfshf_alloc)
#define bfshf_ai (bfshf_alloc | bfshf_write | bfshf_undocumneted)

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

/******************************************************************************/
/* ELF Dynamic Symbol Table                                                   */
/******************************************************************************/

/*
 * ELF Symbol Bindings
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 10
 */
#define bfstb_local ((unsigned char)0)
#define bfstb_global ((unsigned char)1)
#define bfstb_weak ((unsigned char)2)
#define bfstb_loos ((unsigned char)10)
#define bfstb_hios ((unsigned char)12)
#define bfstb_loproc ((unsigned char)13)
#define bfstb_hiproc ((unsigned char)15)

/*
 * ELF Symbol Types
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 10
 */
#define bfstt_notype ((unsigned char)0)
#define bfstt_object ((unsigned char)1)
#define bfstt_func ((unsigned char)2)
#define bfstt_section ((unsigned char)3)
#define bfstt_file ((unsigned char)4)
#define bfstt_loos ((unsigned char)10)
#define bfstt_hios ((unsigned char)12)
#define bfstt_loproc ((unsigned char)13)
#define bfstt_hiproc ((unsigned char)15)

/*
 * ELF Symbol Info Algorithms
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 11
 */
#define BFELF_SYM_BIND(x) ((x) >> 4)
#define BFELF_SYM_TYPE(x) ((x) & 0xF)

/*
 * ELF Undefined Symbol Index
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 9
 */
#define STN_UNDEF 0

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

/******************************************************************************/
/* ELF Relocations                                                            */
/******************************************************************************/

/*
 * System V ABI 64bit Relocations
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.x86-64.org/documentation/abi.pdf, page 71
 */
#define BFR_X86_64_64 ((bfelf64_xword)1)
#define BFR_X86_64_GLOB_DAT ((bfelf64_xword)6)
#define BFR_X86_64_JUMP_SLOT ((bfelf64_xword)7)
#define BFR_X86_64_RELATIVE ((bfelf64_xword)8)

/*
 * ELF Relocation
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 11
 */
struct bfelf_rel
{
    bfelf64_addr r_offset;
    bfelf64_xword r_info;
};

/*
 * ELF Relocation Addend
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 11
 */
struct bfelf_rela
{
    bfelf64_addr r_offset;
    bfelf64_xword r_info;
    bfelf64_sxword r_addend;
};

/*
 * ELF Relocation Info Algorithms
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 11
 */
#define BFELF_REL_SYM(i)  ((i) >> 32)
#define BFELF_REL_TYPE(i) ((i) & 0xFFFFFFFFL)

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

/******************************************************************************/
/* ELF Loader                                                                 */
/******************************************************************************/

/**
 * ELF Loader
 *
 * The following structure is used to create an ELF loader, which groups up
 * all of the ELF files used by a single program, mainly needed for global
 * symbol searching.
 */
struct bfelf_loader_t
{
    bfelf64_word num;
    bfelf64_word relocated;
    struct bfelf_file_t *efs[BFELF_MAX_MODULES];
};

/**
 * Add ELF file to an ELF loader
 *
 * Once an ELF loader has been initialized, use this function to add an
 * ELF file to the ELF loader
 *
 * @param loader the ELF loader
 * @param ef the ELF file to add
 * @param exec the offset into memory where this ELF file is loaded. This is
 *     used during relocations to move a symbol to where it is actually
 *     located. For most libraries, this should be an actual value, while
 *     for more binaries, this is likely 0. Also note that this value should
 *     be relative to the page tables that will be used when the application
 *     is run.
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword bfelf_loader_add(struct bfelf_loader_t *loader,
                               struct bfelf_file_t *ef,
                               char *exec);

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
bfelf64_sword bfelf_loader_relocate(struct bfelf_loader_t *loader);

/**
 * Resolve Symbol
 *
 * Once an ELF loader has had all of it's ELF files initalized and added,
 * use the relocate ELF loader to setup the ELF files such that they can
 * be executed. If the ELF file is relocated into memory that is accessable
 * via the ELF loader, the resolve symbol function can be used to get the
 * address of a specific symbol so that it can be executed.
 *
 * @param loader the ELF loader
 * @param name the name of the symbol to resolve
 * @param addr the resulting address if the symbol is successfully resolved
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword bfelf_loader_resolve_symbol(struct bfelf_loader_t *loader,
        struct e_string_t *name,
        void **addr);

/**
 * Get Info
 *
 * Once an ELF loader has had all of it's ELF files initalized and added,
 * use the relocate ELF loader to setup the ELF files such that they can
 * be executed. Once this is done, this function can be used to get the
 * C runtime information for bootstrapping a binary / module. If the info
 * structure is located in memory that is accessible to the loader, the
 * init and fini functions are provided in the inof structure itself for
 * executing the runtime functions.
 *
 * @param loader the ELF loader
 * @param ef the ELF file to get the info structure for
 * @param info the info structore to store the results.
 * @return BFELF_SUCCESS on success, negative on error
 */
bfelf64_sword bfelf_loader_get_info(struct bfelf_loader_t *loader,
                                    struct bfelf_file_t *ef,
                                    struct section_info_t *info);

#ifdef __cplusplus
}
#endif

#pragma pack(pop)
#endif
