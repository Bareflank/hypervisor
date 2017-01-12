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
#include <types.h>
#include <constants.h>
#include <error_codes.h>

#pragma GCC system_header

#pragma pack(push, 1)

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/
/* ELF Defines                                                                */
/******************************************************************************/

#ifndef BFELF_MAX_NEEDED
#define BFELF_MAX_NEEDED 25
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
/* ELF File                                                                   */
/******************************************************************************/

struct bfelf_dyn;
struct bfelf_sym;
struct bfelf_rela;
struct bfelf_shdr;
struct bfelf_phdr;
struct bfelf_ehdr;

/*
 * ELF Load Segment
 *
 * The load instructions that each segment provides is missing some helpful
 * info. This structure provides the info that is needed, in a cleaned up
 * format.
 */
struct bfelf_load_instr
{
    bfelf64_word perm;
    bfelf64_off mem_offset;
    bfelf64_off file_offset;
    bfelf64_xword memsz;
    bfelf64_xword filesz;
    bfelf64_addr virt_addr;
};

/*
 * ELF File
 *
 * The following is used by this API to store information about the ELF file
 * being used.
 */
struct bfelf_file_t
{
    uint64_t filesz;
    const char *file;

    char *exec_addr;
    char *exec_virt;

    bfelf64_off entry;

    bfelf64_xword num_load_instr;
    struct bfelf_load_instr load_instr[BFELF_MAX_SEGMENTS];

    bfelf64_xword num_loadable_segments;
    struct bfelf_phdr *loadable_segments[BFELF_MAX_SEGMENTS];

    bfelf64_addr start_addr;
    bfelf64_xword total_memsz;

    bfelf64_xword num_needed;
    bfelf64_xword needed[BFELF_MAX_NEEDED];

    struct bfelf_ehdr *ehdr;
    struct bfelf_phdr *phdrtab;
    struct bfelf_shdr *shdrtab;

    bfelf64_addr dynoff;

    char *strtab;

    bfelf64_word nbucket;
    bfelf64_word nchain;
    bfelf64_word *bucket;
    bfelf64_word *chain;
    bfelf64_word *hash;

    bfelf64_xword dynnum;
    struct bfelf_dyn *dyntab;

    bfelf64_xword symnum;
    struct bfelf_sym *symtab;

    bfelf64_xword relanum;
    struct bfelf_rela *relatab;

    bfelf64_addr init;
    bfelf64_addr fini;

    bfelf64_addr init_array;
    bfelf64_xword init_arraysz;

    bfelf64_addr fini_array;
    bfelf64_xword fini_arraysz;

    bfelf64_addr eh_frame;
    bfelf64_xword eh_framesz;

    bfelf64_xword flags_1;
    bfelf64_xword stack_flags;

    bfelf64_addr relaro_vaddr;
    bfelf64_xword relaro_memsz;
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
 * @param filesz the size of the character buffer
 * @param ef the ELF file structure to initialize.
 * @return BFELF_SUCCESS on success, negative on error
 */
int64_t bfelf_file_init(const char *file,
                        uint64_t filesz,
                        struct bfelf_file_t *ef);

/**
 * Get number of load instructions
 *
 * Once an ELF file has been initialized, the next step is to load all of the
 * program segments into memory, relocate them, and then execute the entry
 * point. To assist this operation, this function returns the total number of
 * load instructions.
 *
 * @param ef the ELF file
 * @return number of load instructions on success, negative on error
 */
int64_t bfelf_file_num_load_instrs(struct bfelf_file_t *ef);

/**
 * Get load instructions
 *
 * Once you know how many load instructions there are, you can use this
 * function to get each instruction structure.
 *
 * @param ef the ELF file
 * @param index the index of the instructions to get
 * @param instr where to store the load instructions
 * @return BFELF_SUCCESS on success, negative on error
 */
int64_t bfelf_file_get_load_instr(struct bfelf_file_t *ef,
                                  uint64_t index,
                                  struct bfelf_load_instr **instr);

/**
 * Resolve Symbol
 *
 * Once an ELF loader has had all of it's ELF files initialized and added,
 * use the relocate ELF loader to setup the ELF files such that they can
 * be executed. If the ELF file is relocated into memory that is accessible
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
int64_t bfelf_file_resolve_symbol(struct bfelf_file_t *ef,
                                  const char *name,
                                  void **addr);

/**
 * Get Info
 *
 * Once an ELF loader has had all of it's ELF files initialized and added,
 * use the relocate ELF loader to setup the ELF files such that they can
 * be executed. Once this is done, this function can be used to get the
 * C runtime information for bootstrapping a binary / module.
 *
 * @param ef the ELF file to get the info structure for
 * @param info the info structure to store the results.
 * @return BFELF_SUCCESS on success, negative on error
 */
int64_t bfelf_file_get_section_info(struct bfelf_file_t *ef,
                                    struct section_info_t *info);

/**
 * Get Entry Point
 *
 * Returns the entry point of the ELF file.
 *
 * @param ef the ELF file to get the info structure for
 * @param addr the resulting address of the entry point
 * @return BFELF_SUCCESS on success, negative on error
 */
int64_t bfelf_file_get_entry(struct bfelf_file_t *ef,
                             void **addr);

/**
 * Get Stack Permissions
 *
 * Returns the ELF file's stack permissions.
 *
 * @param ef the ELF file to get the info structure for
 * @param perm the resulting permissions
 * @return BFELF_SUCCESS on success, negative on error
 */
int64_t bfelf_file_get_stack_perm(struct bfelf_file_t *ef,
                                  bfelf64_xword *perm);

/**
 * Get Relocation Read-Only Info
 *
 * Returns the ELF file's RELRO information for
 * re-mapping previously writable memory to read-only
 *
 * @param ef the ELF file to get the info structure for
 * @param addr the resulting address
 * @param size the resulting size
 * @return BFELF_SUCCESS on success, negative on error
 */
int64_t bfelf_file_get_relro(struct bfelf_file_t *ef,
                             bfelf64_addr *addr,
                             bfelf64_xword *size);

/**
 * Get Number of Needed Libraries
 *
 * Returns the number of DT_NEEDED entries in the ELF
 * file
 *
 * @param ef the ELF file to get the info structure for
 * @return number of needed entries on success, negative on error
 */
int64_t bfelf_file_get_num_needed(struct bfelf_file_t *ef);

/**
 * Get Needed Library
 *
 * Returns the name of a shared library that is needed by this
 * ELF file
 *
 * @param ef the ELF file to get the info structure for
 * @param index the shared library name to get
 * @param needed the resulting needed library
 * @return number of needed entries on success, negative on error
 */
int64_t bfelf_file_get_needed(struct bfelf_file_t *ef,
                              uint64_t index,
                              char **needed);

/**
 * Get Total Memory Size
 *
 * Returns the total number of bytes needed in memory for this ELF file
 * when loading the ELF file
 *
 * @param ef the ELF file to get the info structure for
 * @return number of needed entries on success, negative on error
 */
int64_t
bfelf_file_get_total_size(struct bfelf_file_t *ef);

/**
 * Get PIC/PIE
 *
 * Returns 1 if this ELF file was compiled using PIC / PIE, or
 * 0 otherwise
 *
 * @param ef the ELF file to get the info structure for
 * @return 1 if compiled with PIC/PIE, 0 otherwise
 */
int64_t
bfelf_file_get_pic_pie(struct bfelf_file_t *ef);

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
struct bfelf_ehdr
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
#define bfsht_init_array ((bfelf64_word)14)
#define bfsht_fini_array ((bfelf64_word)15)
#define bfsht_loos ((bfelf64_word)0x60000000)
#define bfsht_hios ((bfelf64_word)0x6FFFFFFF)
#define bfsht_loproc ((bfelf64_word)0x70000000)
#define bfsht_x86_64_unwind ((bfelf64_word)0x70000001)
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
/* ELF Dynamic Section                                                        */
/******************************************************************************/

/*
 * ELF Dynamic Table Entry Tags
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 14
 */
#define bfdt_null ((bfelf64_xword)0)
#define bfdt_needed ((bfelf64_xword)1)
#define bfdt_pltrelsz ((bfelf64_xword)2)
#define bfdt_pltgot ((bfelf64_xword)3)
#define bfdt_hash ((bfelf64_xword)4)
#define bfdt_strtab ((bfelf64_xword)5)
#define bfdt_symtab ((bfelf64_xword)6)
#define bfdt_rela ((bfelf64_xword)7)
#define bfdt_relasz ((bfelf64_xword)8)
#define bfdt_relaent ((bfelf64_xword)9)
#define bfdt_strsz ((bfelf64_xword)10)
#define bfdt_syment ((bfelf64_xword)11)
#define bfdt_init ((bfelf64_xword)12)
#define bfdt_fini ((bfelf64_xword)13)
#define bfdt_soname ((bfelf64_xword)14)
#define bfdt_rpath ((bfelf64_xword)15)
#define bfdt_symbolic ((bfelf64_xword)16)
#define bfdt_rel ((bfelf64_xword)17)
#define bfdt_relsz ((bfelf64_xword)18)
#define bfdt_relent ((bfelf64_xword)19)
#define bfdt_pltrel ((bfelf64_xword)20)
#define bfdt_debug ((bfelf64_xword)21)
#define bfdt_textrel ((bfelf64_xword)22)
#define bfdt_jmprel ((bfelf64_xword)23)
#define bfdt_bind_now ((bfelf64_xword)24)
#define bfdt_init_array ((bfelf64_xword)25)
#define bfdt_fini_array ((bfelf64_xword)26)
#define bfdt_init_arraysz ((bfelf64_xword)27)
#define bfdt_fini_arraysz ((bfelf64_xword)28)
#define bfdt_loos ((bfelf64_xword)0x60000000)
#define bfdt_relacount ((bfelf64_xword)0x6ffffff9)
#define bfdt_relcount ((bfelf64_xword)0x6ffffffa)
#define bfdt_flags_1 ((bfelf64_xword)0x6ffffffb)
#define bfdt_hios ((bfelf64_xword)0x6FFFFFFF)
#define bfdt_loproc ((bfelf64_xword)0x70000000)
#define bfdt_hiproc ((bfelf64_xword)0x7FFFFFFF)

#define bfdf_1_now ((bfelf64_xword)0x00000001)
#define bfdf_1_global ((bfelf64_xword)0x00000002)
#define bfdf_1_group ((bfelf64_xword)0x00000004)
#define bfdf_1_nodelete ((bfelf64_xword)0x00000008)
#define bfdf_1_loadfltr ((bfelf64_xword)0x00000010)
#define bfdf_1_initfirst ((bfelf64_xword)0x00000020)
#define bfdf_1_noopen ((bfelf64_xword)0x00000040)
#define bfdf_1_origin ((bfelf64_xword)0x00000080)
#define bfdf_1_direct ((bfelf64_xword)0x00000100)
#define bfdf_1_trans ((bfelf64_xword)0x00000200)
#define bfdf_1_interpose ((bfelf64_xword)0x00000400)
#define bfdf_1_nodeflib ((bfelf64_xword)0x00000800)
#define bfdf_1_nodump ((bfelf64_xword)0x00001000)
#define bfdf_1_confalt ((bfelf64_xword)0x00002000)
#define bfdf_1_endfiltee ((bfelf64_xword)0x00004000)
#define bfdf_1_dispreldne ((bfelf64_xword)0x00008000)
#define bfdf_1_disprelpnd ((bfelf64_xword)0x00010000)
#define bfdf_1_nodirect ((bfelf64_xword)0x00020000)
#define bfdf_1_ignmuldef ((bfelf64_xword)0x00040000)
#define bfdf_1_noksyms ((bfelf64_xword)0x00080000)
#define bfdf_1_nohdr ((bfelf64_xword)0x00100000)
#define bfdf_1_edited ((bfelf64_xword)0x00200000)
#define bfdf_1_noreloc ((bfelf64_xword)0x00400000)
#define bfdf_1_symintpose ((bfelf64_xword)0x00800000)
#define bfdf_1_globaudit ((bfelf64_xword)0x01000000)
#define bfdf_1_singleton ((bfelf64_xword)0x02000000)
#define bfdf_1_pie ((bfelf64_xword) 0x08000000)

/*
 * ELF Dynamic Table
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 14
 *
 * NOTE: The spec actually uses a union, but the use of a union goes against
 * the C++ Core Guidelines, and Windows seems to get really mad. There really
 * is not need for a union since the type size if the same. For this reason,
 * we simply use d_val and cast when needed.
 *
 */
struct bfelf_dyn
{
    bfelf64_sxword d_tag;
    bfelf64_xword d_val;
};

/******************************************************************************/
/* ELF Symbol Table                                                           */
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
#define bfpt_gnu_eh_frame ((bfelf64_word)0x6474e550)
#define bfpt_gnu_stack ((bfelf64_word)0x6474e551)
#define bfpt_gnu_relro ((bfelf64_word)0x6474e552)
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
    struct bfelf_file_t *efs[MAX_NUM_MODULES];
};

/**
 * Add ELF file to an ELF loader
 *
 * Once an ELF loader has been initialized, use this function to add an
 * ELF file to the ELF loader
 *
 * @param loader the ELF loader
 * @param ef the ELF file to add
 * @param exec_addr the address in memory where this ELF file was loaded.
 * @param exec_virt the address in memory where this ELF file will be run.
 * @return BFELF_SUCCESS on success, negative on error
 */
int64_t bfelf_loader_add(struct bfelf_loader_t *loader,
                         struct bfelf_file_t *ef,
                         char *exec_addr,
                         char *exec_virt);

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
int64_t bfelf_loader_relocate(struct bfelf_loader_t *loader);

/**
 * Resolve Symbol
 *
 * Once an ELF loader has had all of it's ELF files initialized and added,
 * use the relocate ELF loader to setup the ELF files such that they can
 * be executed. If the ELF file is relocated into memory that is accessible
 * via the ELF loader, the resolve symbol function can be used to get the
 * address of a specific symbol so that it can be executed.
 *
 * @param loader the ELF loader
 * @param name the name of the symbol to resolve
 * @param addr the resulting address if the symbol is successfully resolved
 * @return BFELF_SUCCESS on success, negative on error
 */
int64_t bfelf_loader_resolve_symbol(struct bfelf_loader_t *loader,
                                    const char *name,
                                    void **addr);

#ifdef __cplusplus
}
#endif

#pragma pack(pop)
#endif
