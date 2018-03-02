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

/**
 * @file bfelf_loader.h
 */

#ifndef BFELF_LOADER_H
#define BFELF_LOADER_H

#include <debug.h>
#include <constants.h>
#include <crt.h>
#include <error_codes.h>
#include <types.h>

#pragma GCC system_header

#pragma pack(push, 1)

/* @cond */

#ifdef __cplusplus
#define scast(a, b) (static_cast<a>(b))
#else
#define scast(a, b) ((a)(b))
#endif

#ifdef __cplusplus
#define rcast(a, b) (reinterpret_cast<a>(b))
#else
#define rcast(a, b) ((a)(b))
#endif

#ifdef __cplusplus
#define add(a, b, c) (reinterpret_cast<a>(reinterpret_cast<const char *>(b) + (c)))
#else
#define add(a, b, c) ((a)((const char *)(b) + (c)))
#endif

/* @endcond */

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------------------------------- */
/* ELF Defines                                                                                    */
/* ---------------------------------------------------------------------------------------------- */

/* @cond */

#ifndef BFELF_MAX_NEEDED
#define BFELF_MAX_NEEDED (25)
#endif

#ifndef BFELF_MAX_SEGMENTS
#define BFELF_MAX_SEGMENTS (4)
#endif

/* @endcond */

/* ---------------------------------------------------------------------------------------------- */
/* ELF Data Types                                                                                 */
/* ---------------------------------------------------------------------------------------------- */

/*
 * Data Representation
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 2
 */

/* @cond */

typedef uint64_t bfelf64_addr;
typedef uint64_t bfelf64_off;
typedef uint16_t bfelf64_half;
typedef uint32_t bfelf64_word;
typedef int32_t bfelf64_sword;
typedef uint64_t bfelf64_xword;
typedef int64_t bfelf64_sxword;

/* @endcond */

/* ---------------------------------------------------------------------------------------------- */
/* ELF Error Codes                                                                                */
/* ---------------------------------------------------------------------------------------------- */

/* @cond */

static inline int64_t
private_error(const char *header, const char *msg, const char *func, int line, int64_t code)
{
    ALERT("%s [%d] %s: %s\n", func, line, header, msg);
    return code;
}

#define bfinvalid_argument(a)                                                                      \
    private_error("invalid argument", a, __func__, __LINE__, BFELF_ERROR_INVALID_ARG);

#define bfinvalid_file(a)                                                                          \
    private_error("invalid file", a, __func__, __LINE__, BFELF_ERROR_INVALID_FILE);

#define bfinvalid_index(a)                                                                         \
    private_error("invalid index", a, __func__, __LINE__, BFELF_ERROR_INVALID_INDEX);

#define bfinvalid_signature(a)                                                                     \
    private_error("invalid signature", a, __func__, __LINE__, BFELF_ERROR_INVALID_SIGNATURE);

#define bfunsupported_file(a)                                                                      \
    private_error("unsupported elf file", a, __func__, __LINE__, BFELF_ERROR_UNSUPPORTED_FILE);

#define bfloader_full(a)                                                                           \
    private_error("loader full", a, __func__, __LINE__, BFELF_ERROR_LOADER_FULL);

#define bfno_such_symbol(a)                                                                        \
    private_error("no such symbol", a, __func__, __LINE__, BFELF_ERROR_NO_SUCH_SYMBOL);

#define bfunsupported_rel(a)                                                                       \
    private_error("unsupported relocation", a, __func__, __LINE__, BFELF_ERROR_UNSUPPORTED_RELA);

/* @endcond */

/* ---------------------------------------------------------------------------------------------- */
/* ELF Helpers                                                                                    */
/* ---------------------------------------------------------------------------------------------- */

/* @cond */

static inline int64_t
private_strcmp(const char *s1, const char *s2)
{
    while (*s1 && (*s1 == *s2))
        s1++, s2++;

    return *s1 == *s2 ? BFELF_SUCCESS : BFELF_ERROR_MISMATCH;
}

/* @endcond */

/* ---------------------------------------------------------------------------------------------- */
/* ELF File Definition                                                                            */
/* ---------------------------------------------------------------------------------------------- */

struct bfelf_dyn;
struct bfelf_sym;
struct bfelf_rela;
struct bfelf_shdr;
struct bfelf_phdr;
struct bfelf_ehdr;

/**
 * @struct bfelf_load_instr
 *
 * ELF Load Segment
 *
 * The load instructions that each segment provides is missing some helpful
 * info. This structure provides the info that is needed, in a cleaned up
 * format.
 *
 * Note that there are two different char * buffers that you need to know about
 * when loading a segment. There is the char * for the ELF file, and the char *
 * for the memory that the ELF file is being loaded into. The ELF file does
 * not equal memory. The best example is the BSS section, which is empty in the
 * ELF file. Also, the RE vs RW sections are usually aligned. To use this
 * information use the following steps:
 * - get the total size of memory
 * - allocate RW memory for the total size
 * - get the number of load instructions
 * - loop through each load instruction and copy the file char * to the mem
 *   char * using the file/mem offset/size.
 * - map memory using the virt_addr and mem_size
 *
 * @var bfelf_load_instr::perm
 *      defines the permissions (read/write/execute) for this segment
 * @var bfelf_load_instr::mem_offset
 *      defines the segment offset in memory
 * @var bfelf_load_instr::file_offset
 *      defines the segment offset in the ELF file
 * @var bfelf_load_instr::memsz
 *      defines the segment size in memory
 * @var bfelf_load_instr::filesz
 *      defines the segment size in the ELF file
 * @var bfelf_load_instr::virt_addr
 *      defines the assumed virtual address of the segment if PIC == false
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
 *
 * @cond
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
    const struct bfelf_phdr *loadable_segments[BFELF_MAX_SEGMENTS];

    bfelf64_addr start_addr;
    bfelf64_xword total_memsz;

    bfelf64_xword num_needed;
    bfelf64_xword needed[BFELF_MAX_NEEDED];

    const struct bfelf_ehdr *ehdr;
    const struct bfelf_phdr *phdrtab;
    const struct bfelf_shdr *shdrtab;

    bfelf64_addr dynoff;

    const char *strtab;
    const char *shstrtab;

    bfelf64_word nbucket;
    bfelf64_word nchain;
    const bfelf64_word *bucket;
    const bfelf64_word *chain;
    const bfelf64_word *hash;

    bfelf64_xword dynnum;
    const struct bfelf_dyn *dyntab;

    bfelf64_xword symnum;
    const struct bfelf_sym *symtab;

    bfelf64_xword relanum_dyn;
    const struct bfelf_rela *relatab_dyn;

    bfelf64_xword relanum_plt;
    const struct bfelf_rela *relatab_plt;

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

    bfelf64_word added;
};

/* @endcond */

/* ---------------------------------------------------------------------------------------------- */
/* ELF File Header                                                                                */
/* ---------------------------------------------------------------------------------------------- */

/*
 * e_ident indexes
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 3
 *
 * @cond
 */
#define bfei_mag0 scast(bfelf64_sword, 0)
#define bfei_mag1 scast(bfelf64_sword, 1)
#define bfei_mag2 scast(bfelf64_sword, 2)
#define bfei_mag3 scast(bfelf64_sword, 3)
#define bfei_class scast(bfelf64_sword, 4)
#define bfei_data scast(bfelf64_sword, 5)
#define bfei_version scast(bfelf64_sword, 6)
#define bfei_osabi scast(bfelf64_sword, 7)
#define bfei_abiversion scast(bfelf64_sword, 8)
#define bfei_pad scast(bfelf64_sword, 9)
#define bfei_nident scast(bfelf64_sword, 16)

/* @endcond */

/*
 * ELF Class Types
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 5
 *
 * @cond
 */
#define bfelfclass32 scast(unsigned char, 1)
#define bfelfclass64 scast(unsigned char, 2)

/* @endcond */

/*
 * ELF Data Types
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 5
 *
 * @cond
 */
#define bfelfdata2lsb scast(unsigned char, 1)
#define bfelfdata2msb scast(unsigned char, 2)

/* @endcond */

/*
 * ELF Version
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 4
 *
 * @cond
 */
#define bfev_current scast(unsigned char, 1)

/* @endcond */

/*
 * ELF OS / ABI Types
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 5
 *
 * @cond
 */
#define bfelfosabi_sysv scast(unsigned char, 0)
#define bfelfosabi_hpux scast(unsigned char, 1)
#define bfelfosabi_standalone scast(unsigned char, 255)

/* @endcond */

/*
 * ELF Types
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 5
 *
 * @cond
 */
#define bfet_none scast(bfelf64_half, 0)
#define bfet_rel scast(bfelf64_half, 1)
#define bfet_exec scast(bfelf64_half, 2)
#define bfet_dyn scast(bfelf64_half, 3)
#define bfet_core scast(bfelf64_half, 4)
#define bfet_loos scast(bfelf64_half, 0xFE00)
#define bfet_hios scast(bfelf64_half, 0xFEFF)
#define bfet_loproc scast(bfelf64_half, 0xFF00)
#define bfet_hiproc scast(bfelf64_half, 0xFFFF)

/* @endcond */

/*
 * ELF Machine Codes
 *
 * The following is defined in the Linux kernel sources:
 * linux/include/uapi/linux/elf-em.h
 *
 * @cond
 */
#define bfem_none scast(bfelf64_half, 0)
#define bfem_m32 scast(bfelf64_half, 1)
#define bfem_sparc scast(bfelf64_half, 2)
#define bfem_386 scast(bfelf64_half, 3)
#define bfem_68k scast(bfelf64_half, 4)
#define bfem_88k scast(bfelf64_half, 5)
#define bfem_486 scast(bfelf64_half, 6)
#define bfem_860 scast(bfelf64_half, 7)
#define bfem_mips scast(bfelf64_half, 8)
#define bfem_mips_rs3_le scast(bfelf64_half, 10)
#define bfem_mips_rs4_be scast(bfelf64_half, 11)
#define bfem_parisc scast(bfelf64_half, 15)
#define bfem_sparc32plus scast(bfelf64_half, 18)
#define bfem_ppc scast(bfelf64_half, 20)
#define bfem_ppc64 scast(bfelf64_half, 21)
#define bfem_spu scast(bfelf64_half, 23)
#define bfem_arm scast(bfelf64_half, 40)
#define bfem_sh scast(bfelf64_half, 42)
#define bfem_sparcv9 scast(bfelf64_half, 43)
#define bfem_h8_300 scast(bfelf64_half, 46)
#define bfem_ia_64 scast(bfelf64_half, 50)
#define bfem_x86_64 scast(bfelf64_half, 62)
#define bfem_s390 scast(bfelf64_half, 22)
#define bfem_cris scast(bfelf64_half, 76)
#define bfem_v850 scast(bfelf64_half, 87)
#define bfem_m32r scast(bfelf64_half, 88)
#define bfem_mn10300 scast(bfelf64_half, 89)
#define bfem_openrisc scast(bfelf64_half, 92)
#define bfem_blackfin scast(bfelf64_half, 106)
#define bfem_altera_nios2 scast(bfelf64_half, 113)
#define bfem_ti_c6000 scast(bfelf64_half, 140)
#define bfem_aarch64 scast(bfelf64_half, 183)
#define bfem_frv scast(bfelf64_half, 0x5441)
#define bfem_avr32 scast(bfelf64_half, 0x18AD)
#define bfem_alpha scast(bfelf64_half, 0x9026)
#define bfem_cygnus_v850 scast(bfelf64_half, 0x9080)
#define bfem_cygnus_m32r scast(bfelf64_half, 0x9041)
#define bfem_s390_old scast(bfelf64_half, 0xA390)
#define bfem_cygnus_mn10300 scast(bfelf64_half, 0xBEEF)

/* @endcond */

/*
 * ELF File Header
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 3
 *
 * The file header is located at the beginning of the file, and is used to
 * locate the other parts of the file.
 *
 * @cond
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

/* @endcond */

/* ---------------------------------------------------------------------------------------------- */
/* ELF Section Header Table                                                                       */
/* ---------------------------------------------------------------------------------------------- */

/*
 * ELF Section Type
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 7
 *
 * @cond
 */
#define bfsht_null scast(bfelf64_word, 0)
#define bfsht_progbits scast(bfelf64_word, 1)
#define bfsht_symtab scast(bfelf64_word, 2)
#define bfsht_strtab scast(bfelf64_word, 3)
#define bfsht_rela scast(bfelf64_word, 4)
#define bfsht_hash scast(bfelf64_word, 5)
#define bfsht_dynamic scast(bfelf64_word, 6)
#define bfsht_note scast(bfelf64_word, 7)
#define bfsht_nobits scast(bfelf64_word, 8)
#define bfsht_rel scast(bfelf64_word, 9)
#define bfsht_shlib scast(bfelf64_word, 10)
#define bfsht_dynsym scast(bfelf64_word, 11)
#define bfsht_init_array scast(bfelf64_word, 14)
#define bfsht_fini_array scast(bfelf64_word, 15)
#define bfsht_loos scast(bfelf64_word, 0x60000000)
#define bfsht_hios scast(bfelf64_word, 0x6FFFFFFF)
#define bfsht_loproc scast(bfelf64_word, 0x70000000)
#define bfsht_x86_64_unwind scast(bfelf64_word, 0x70000001)
#define bfsht_hiproc scast(bfelf64_word, 0x7FFFFFFF)

/* @endcond */

/*
 * ELF Section Attributes
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 8
 *
 * @cond
 */
#define bfshf_write scast(bfelf64_xword, 0x1)
#define bfshf_alloc scast(bfelf64_xword, 0x2)
#define bfshf_execinstr scast(bfelf64_xword, 0x4)
#define bfshf_maskos scast(bfelf64_xword, 0x0F000000)
#define bfshf_maskproc scast(bfelf64_xword, 0xF0000000)
#define bfshf_undocumneted scast(bfelf64_xword, 0x00000060)

#define bfshf_a (bfshf_alloc)
#define bfshf_wa (bfshf_write | bfshf_alloc)
#define bfshf_ai (bfshf_alloc | bfshf_write | bfshf_undocumneted)

/* @endcond */

/*
 * ELF Section Header Entry
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 6
 *
 * Sections contain all the information in an ELF file, except for the ELF
 * header, program header table, and section header table. Sections are
 * identified by an index into the section header table.
 *
 * @cond
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

/* @endcond */

/* ---------------------------------------------------------------------------------------------- */
/* ELF Dynamic Section                                                                            */
/* ---------------------------------------------------------------------------------------------- */

/*
 * ELF Dynamic Table Entry Tags
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 14
 *
 * @cond
 */
#define bfdt_null scast(bfelf64_xword, 0)
#define bfdt_needed scast(bfelf64_xword, 1)
#define bfdt_pltrelsz scast(bfelf64_xword, 2)
#define bfdt_pltgot scast(bfelf64_xword, 3)
#define bfdt_hash scast(bfelf64_xword, 4)
#define bfdt_strtab scast(bfelf64_xword, 5)
#define bfdt_symtab scast(bfelf64_xword, 6)
#define bfdt_rela scast(bfelf64_xword, 7)
#define bfdt_relasz scast(bfelf64_xword, 8)
#define bfdt_relaent scast(bfelf64_xword, 9)
#define bfdt_strsz scast(bfelf64_xword, 10)
#define bfdt_syment scast(bfelf64_xword, 11)
#define bfdt_init scast(bfelf64_xword, 12)
#define bfdt_fini scast(bfelf64_xword, 13)
#define bfdt_soname scast(bfelf64_xword, 14)
#define bfdt_rpath scast(bfelf64_xword, 15)
#define bfdt_symbolic scast(bfelf64_xword, 16)
#define bfdt_rel scast(bfelf64_xword, 17)
#define bfdt_relsz scast(bfelf64_xword, 18)
#define bfdt_relent scast(bfelf64_xword, 19)
#define bfdt_pltrel scast(bfelf64_xword, 20)
#define bfdt_debug scast(bfelf64_xword, 21)
#define bfdt_textrel scast(bfelf64_xword, 22)
#define bfdt_jmprel scast(bfelf64_xword, 23)
#define bfdt_bind_now scast(bfelf64_xword, 24)
#define bfdt_init_array scast(bfelf64_xword, 25)
#define bfdt_fini_array scast(bfelf64_xword, 26)
#define bfdt_init_arraysz scast(bfelf64_xword, 27)
#define bfdt_fini_arraysz scast(bfelf64_xword, 28)
#define bfdt_loos scast(bfelf64_xword, 0x60000000)
#define bfdt_relacount scast(bfelf64_xword, 0x6ffffff9)
#define bfdt_relcount scast(bfelf64_xword, 0x6ffffffa)
#define bfdt_flags_1 scast(bfelf64_xword, 0x6ffffffb)
#define bfdt_hios scast(bfelf64_xword, 0x6FFFFFFF)
#define bfdt_loproc scast(bfelf64_xword, 0x70000000)
#define bfdt_hiproc scast(bfelf64_xword, 0x7FFFFFFF)

#define bfdf_1_now scast(bfelf64_xword, 0x00000001)
#define bfdf_1_global scast(bfelf64_xword, 0x00000002)
#define bfdf_1_group scast(bfelf64_xword, 0x00000004)
#define bfdf_1_nodelete scast(bfelf64_xword, 0x00000008)
#define bfdf_1_loadfltr scast(bfelf64_xword, 0x00000010)
#define bfdf_1_initfirst scast(bfelf64_xword, 0x00000020)
#define bfdf_1_noopen scast(bfelf64_xword, 0x00000040)
#define bfdf_1_origin scast(bfelf64_xword, 0x00000080)
#define bfdf_1_direct scast(bfelf64_xword, 0x00000100)
#define bfdf_1_trans scast(bfelf64_xword, 0x00000200)
#define bfdf_1_interpose scast(bfelf64_xword, 0x00000400)
#define bfdf_1_nodeflib scast(bfelf64_xword, 0x00000800)
#define bfdf_1_nodump scast(bfelf64_xword, 0x00001000)
#define bfdf_1_confalt scast(bfelf64_xword, 0x00002000)
#define bfdf_1_endfiltee scast(bfelf64_xword, 0x00004000)
#define bfdf_1_dispreldne scast(bfelf64_xword, 0x00008000)
#define bfdf_1_disprelpnd scast(bfelf64_xword, 0x00010000)
#define bfdf_1_nodirect scast(bfelf64_xword, 0x00020000)
#define bfdf_1_ignmuldef scast(bfelf64_xword, 0x00040000)
#define bfdf_1_noksyms scast(bfelf64_xword, 0x00080000)
#define bfdf_1_nohdr scast(bfelf64_xword, 0x00100000)
#define bfdf_1_edited scast(bfelf64_xword, 0x00200000)
#define bfdf_1_noreloc scast(bfelf64_xword, 0x00400000)
#define bfdf_1_symintpose scast(bfelf64_xword, 0x00800000)
#define bfdf_1_globaudit scast(bfelf64_xword, 0x01000000)
#define bfdf_1_singleton scast(bfelf64_xword, 0x02000000)
#define bfdf_1_pie scast(bfelf64_xword, 0x08000000)

/* @endcond */

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
 * @cond
 */
struct bfelf_dyn
{
    bfelf64_sxword d_tag;
    bfelf64_xword d_val;
};

/* @endcond */

/* ---------------------------------------------------------------------------------------------- */
/* ELF Symbol Table                                                                               */
/* ---------------------------------------------------------------------------------------------- */

/*
 * ELF Symbol Bindings
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 10
 *
 * @cond
 */
#define bfstb_local scast(unsigned char, 0)
#define bfstb_global scast(unsigned char, 1)
#define bfstb_weak scast(unsigned char, 2)
#define bfstb_loos scast(unsigned char, 10)
#define bfstb_hios scast(unsigned char, 12)
#define bfstb_loproc scast(unsigned char, 13)
#define bfstb_hiproc scast(unsigned char, 15)

/* @endcond */

/*
 * ELF Symbol Types
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 10
 *
 * @cond
 */
#define bfstt_notype scast(unsigned char, 0)
#define bfstt_object scast(unsigned char, 1)
#define bfstt_func scast(unsigned char, 2)
#define bfstt_section scast(unsigned char, 3)
#define bfstt_file scast(unsigned char, 4)
#define bfstt_loos scast(unsigned char, 10)
#define bfstt_hios scast(unsigned char, 12)
#define bfstt_loproc scast(unsigned char, 13)
#define bfstt_hiproc scast(unsigned char, 15)

/* @endcond */

/*
 * ELF Symbol Info Algorithms
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 11
 *
 * @cond
 */
#define BFELF_SYM_BIND(x) ((x) >> 4)
#define BFELF_SYM_TYPE(x) ((x)&0xF)

/* @endcond */

/*
 * ELF Undefined Symbol Index
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 9
 *
 * @cond
 */
#define STN_UNDEF 0

/* @endcond */

/*
 * ELF Symbol
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 9
 *
 * @cond
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

/* @endcond */

/* ---------------------------------------------------------------------------------------------- */
/* ELF Relocations                                                                                */
/* ---------------------------------------------------------------------------------------------- */

/*
 * System V ABI 64bit Relocations
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.x86-64.org/documentation/abi.pdf, page 71
 *
 * @cond
 */
#define BFR_X86_64_64 scast(bfelf64_xword, 1)
#define BFR_X86_64_GLOB_DAT scast(bfelf64_xword, 6)
#define BFR_X86_64_JUMP_SLOT scast(bfelf64_xword, 7)
#define BFR_X86_64_RELATIVE scast(bfelf64_xword, 8)

/* @endcond */

/*
 * ELF Relocation
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 11
 *
 * @cond
 */
struct bfelf_rel
{
    bfelf64_addr r_offset;
    bfelf64_xword r_info;
};

/* @endcond */

/*
 * ELF Relocation Addend
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 11
 *
 * @cond
 */
struct bfelf_rela
{
    bfelf64_addr r_offset;
    bfelf64_xword r_info;
    bfelf64_sxword r_addend;
};

/* @endcond */

/*
 * ELF Relocation Info Algorithms
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 11
 *
 * @cond
 */
#define BFELF_REL_SYM(i) ((i) >> 32)
#define BFELF_REL_TYPE(i) ((i)&0xFFFFFFFFL)

/* @endcond */

/* ---------------------------------------------------------------------------------------------- */
/* ELF Program Header                                                                             */
/* ---------------------------------------------------------------------------------------------- */

/*
 * ELF Section Attributes
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 12
 *
 * @cond
 */
#define bfpt_null scast(bfelf64_word, 0)
#define bfpt_load scast(bfelf64_word, 1)
#define bfpt_dynamic scast(bfelf64_word, 2)
#define bfpt_interp scast(bfelf64_word, 3)
#define bfpt_note scast(bfelf64_word, 4)
#define bfpt_shlib scast(bfelf64_word, 5)
#define bfpt_phdr scast(bfelf64_word, 6)
#define bfpt_loos scast(bfelf64_word, 0x60000000)
#define bfpt_gnu_eh_frame scast(bfelf64_word, 0x6474e550)
#define bfpt_gnu_stack scast(bfelf64_word, 0x6474e551)
#define bfpt_gnu_relro scast(bfelf64_word, 0x6474e552)
#define bfpt_hios scast(bfelf64_word, 0x6FFFFFFF)
#define bfpt_loproc scast(bfelf64_word, 0x70000000)
#define bfpt_hiproc scast(bfelf64_word, 0x7FFFFFFF)

/* @endcond */

/*
 * ELF Section Attributes
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 13
 *
 * @cond
 */
#define bfpf_x scast(bfelf64_xword, 0x1)
#define bfpf_w scast(bfelf64_xword, 0x2)
#define bfpf_r scast(bfelf64_xword, 0x4)
#define bfpf_maskos scast(bfelf64_xword, 0x00FF0000)
#define bfpf_maskproc scast(bfelf64_xword, 0xFF000000)

/* @endcond */

/*
 * ELF Program Header Entry
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 12
 *
 * In executable and shared object files, sections are grouped into segments for
 * loading. The program header table contains a list of entries describing
 * each segment. This information is needed when using the ELF loader to
 * load each segment into memory allocated by the user. For more information
 * on how to do this, please see the unit tests.
 *
 * @cond
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

/* @endcond */

/* ---------------------------------------------------------------------------------------------- */
/* ELF Loader Definition                                                                          */
/* ---------------------------------------------------------------------------------------------- */

/*
 * ELF Loader
 *
 * The following structure is used to create an ELF loader, which groups up
 * all of the ELF files used by a single program, mainly needed for global
 * symbol searching.
 *
 * @cond
 */
struct bfelf_loader_t
{
    bfelf64_word num;
    bfelf64_word relocated;
    struct bfelf_file_t *efs[MAX_NUM_MODULES];
};

/* @endcond */

/* ---------------------------------------------------------------------------------------------- */
/* ELF Symbol Table Implementation                                                                */
/* ---------------------------------------------------------------------------------------------- */

/* @cond */

static inline unsigned long
private_hash(const char *name)
{
    unsigned long h = 0, g;

    while (*name)
    {
        char c = *name++;
        unsigned char uc = scast(unsigned char, c);

        if (c >= 0)
        {
            h = (h << 4) + uc;
        }
        else
        {
            h = (h << 4) - uc;
        }

        if ((g = (h & 0xf0000000)))
        {
            h ^= g >> 24;
        }

        h &= 0x0fffffff;
    }

    return h;
}

static inline int64_t
private_get_sym_by_hash(struct bfelf_file_t *ef, const char *name, const struct bfelf_sym **sym)
{
    int64_t ret = 0;
    bfelf64_word i = 0;
    unsigned long x = private_hash(name);

    i = ef->bucket[x % ef->nbucket];
    while (i > STN_UNDEF && i < ef->nchain)
    {
        const char *str = 0;

        *sym = &(ef->symtab[i]);
        str = &(ef->strtab[(*sym)->st_name]);

        ret = private_strcmp(name, str);
        if (ret == BFELF_ERROR_MISMATCH)
        {
            i = ef->chain[i];
            continue;
        }

        return BFELF_SUCCESS;
    }

    return BFELF_ERROR_NO_SUCH_SYMBOL;
}

static inline int64_t
private_get_sym_by_name(struct bfelf_file_t *ef, const char *name, const struct bfelf_sym **sym)
{
    int64_t ret = 0;
    bfelf64_word i = 0;

    if (ef->hash != 0)
    {
        return private_get_sym_by_hash(ef, name, sym);
    }

    for (i = 0; i < ef->symnum; i++)
    {
        const char *str = 0;

        *sym = &(ef->symtab[i]);
        str = &(ef->strtab[(*sym)->st_name]);

        ret = private_strcmp(name, str);
        if (ret == BFELF_ERROR_MISMATCH)
        {
            continue;
        }

        return BFELF_SUCCESS;
    }

    return BFELF_ERROR_NO_SUCH_SYMBOL;
}

static inline int64_t
private_get_sym_global(
    struct bfelf_loader_t *loader,
    const char *name,
    struct bfelf_file_t **ef_found,
    const struct bfelf_sym **sym)
{
    int64_t ret = 0;
    bfelf64_word i = 0;
    const struct bfelf_sym *found_sym = 0;
    struct bfelf_file_t *ef_ignore = *ef_found;

    *sym = 0;
    *ef_found = 0;

    for (i = 0; i < loader->num; i++)
    {
        if (loader->efs[i] == ef_ignore)
        {
            continue;
        }

        ret = private_get_sym_by_name(loader->efs[i], name, &found_sym);
        if (ret == BFELF_ERROR_NO_SUCH_SYMBOL)
        {
            continue;
        }

        if (found_sym->st_value == 0)
            continue;

        *sym = found_sym;
        *ef_found = loader->efs[i];

        if (BFELF_SYM_BIND(found_sym->st_info) == bfstb_weak)
        {
            continue;
        }

        return BFELF_SUCCESS;
    }

    if (*sym != 0)
    {
        return BFELF_SUCCESS;
    }

    return bfno_such_symbol(name);
}

/* @endcond */

/* ---------------------------------------------------------------------------------------------- */
/* ELF Relocations Implementation                                                                 */
/* ---------------------------------------------------------------------------------------------- */

/* @cond */

static inline int64_t
private_relocate_symbol(
    struct bfelf_loader_t *loader, struct bfelf_file_t *ef, const struct bfelf_rela *rela)
{
    int64_t ret = 0;
    const char *str = 0;
    const struct bfelf_sym *found_sym = 0;
    struct bfelf_file_t *found_ef = ef;
    bfelf64_addr *ptr = rcast(bfelf64_addr *, ef->exec_addr + rela->r_offset - ef->start_addr);

    if (BFELF_REL_TYPE(rela->r_info) == BFR_X86_64_RELATIVE)
    {
        *ptr = rcast(bfelf64_addr, ef->exec_virt + rela->r_addend);
        return BFELF_SUCCESS;
    }

    found_sym = &(ef->symtab[BFELF_REL_SYM(rela->r_info)]);

    if (BFELF_SYM_BIND(found_sym->st_info) == bfstb_weak)
    {
        found_ef = 0;
    }

    if (found_sym->st_value == 0 || found_ef == 0)
    {
        str = &(ef->strtab[found_sym->st_name]);

        ret = private_get_sym_global(loader, str, &found_ef, &found_sym);
        if (ret != BFELF_SUCCESS)
        {
            return ret;
        }
    }

    *ptr = rcast(bfelf64_addr, found_ef->exec_virt + found_sym->st_value);

    switch (BFELF_REL_TYPE(rela->r_info))
    {
        case BFR_X86_64_64:
            *ptr += scast(bfelf64_addr, rela->r_addend);
            break;

        case BFR_X86_64_GLOB_DAT:
        case BFR_X86_64_JUMP_SLOT:
            break;

        default:
            return bfunsupported_rel(str);
    }

    return BFELF_SUCCESS;
}

static inline int64_t
private_relocate_symbols(struct bfelf_loader_t *loader, struct bfelf_file_t *ef)
{
    int64_t ret = 0;
    bfelf64_word i = 0;

    for (i = 0; i < ef->relanum_dyn; i++)
    {
        const struct bfelf_rela *rela = &(ef->relatab_dyn[i]);

        ret = private_relocate_symbol(loader, ef, rela);
        if (ret != BFELF_SUCCESS)
        {
            return ret;
        }
    }

    for (i = 0; i < ef->relanum_plt; i++)
    {
        const struct bfelf_rela *rela = &(ef->relatab_plt[i]);

        ret = private_relocate_symbol(loader, ef, rela);
        if (ret != BFELF_SUCCESS)
        {
            return ret;
        }
    }

    return BFELF_SUCCESS;
}

/* @endcond */

/* ---------------------------------------------------------------------------------------------- */
/* ELF File Implementation                                                                        */
/* ---------------------------------------------------------------------------------------------- */

/* @cond */

static inline int64_t
private_check_signature(struct bfelf_file_t *ef)
{
    if (ef->ehdr->e_ident[bfei_mag0] != 0x7F)
    {
        return bfinvalid_signature("magic #0 has unexpected value");
    }

    if (ef->ehdr->e_ident[bfei_mag1] != 'E')
    {
        return bfinvalid_signature("magic #1 has unexpected value");
    }

    if (ef->ehdr->e_ident[bfei_mag2] != 'L')
    {
        return bfinvalid_signature("magic #2 has unexpected value");
    }

    if (ef->ehdr->e_ident[bfei_mag3] != 'F')
    {
        return bfinvalid_signature("magic #3 has unexpected value");
    }

    return BFELF_SUCCESS;
}

static inline int64_t
private_check_support(struct bfelf_file_t *ef)
{
    if (ef->ehdr->e_ident[bfei_class] != bfelfclass64)
    {
        return bfunsupported_file("file is not 64bit");
    }

    if (ef->ehdr->e_ident[bfei_data] != bfelfdata2lsb)
    {
        return bfunsupported_file("file is not little endian");
    }

    if (ef->ehdr->e_ident[bfei_version] != bfev_current)
    {
        return bfunsupported_file("unsupported version");
    }

    if (ef->ehdr->e_ident[bfei_osabi] != bfelfosabi_sysv)
    {
        return bfunsupported_file("file does not use the system v abi");
    }

    if (ef->ehdr->e_ident[bfei_abiversion] != 0)
    {
        return bfunsupported_file("unsupported abi version");
    }

    if (ef->ehdr->e_type != bfet_dyn && ef->ehdr->e_type != bfet_exec)
    {
        return bfunsupported_file("file must be an executable or shared library");
    }

    if (ef->ehdr->e_machine != bfem_x86_64)
    {
        return bfunsupported_file("file must be compiled for x86_64");
    }

    if (ef->ehdr->e_version != bfev_current)
    {
        return bfunsupported_file("unsupported version");
    }

    if (ef->ehdr->e_flags != 0)
    {
        return bfunsupported_file("unsupported flags");
    }

    return BFELF_SUCCESS;
}

static inline void
private_process_segments(struct bfelf_file_t *ef)
{
    bfelf64_xword i = 0;

    for (i = 0; i < ef->ehdr->e_phnum; i++)
    {
        const struct bfelf_phdr *phdr = &(ef->phdrtab[i]);

        switch (phdr->p_type)
        {
            case bfpt_load:

                if (ef->num_loadable_segments < BFELF_MAX_SEGMENTS)
                {
                    ef->total_memsz = phdr->p_vaddr + phdr->p_memsz;
                    ef->loadable_segments[ef->num_loadable_segments++] = phdr;
                }

                break;

            case bfpt_dynamic:
                ef->dynoff = phdr->p_offset;
                ef->dynnum = phdr->p_filesz / sizeof(struct bfelf_dyn);
                break;

            case bfpt_gnu_stack:
                ef->stack_flags = phdr->p_flags;
                break;

            case bfpt_gnu_relro:
                ef->relaro_vaddr = phdr->p_vaddr;
                ef->relaro_memsz = phdr->p_memsz;
                break;
        }
    }

    if (ef->num_loadable_segments > 0)
    {
        ef->start_addr = ef->loadable_segments[0]->p_vaddr;
        ef->total_memsz -= ef->start_addr;
    }

    for (i = 0; i < ef->num_loadable_segments; i++)
    {
        const struct bfelf_phdr *phdr = ef->loadable_segments[i];

        ef->load_instr[i].perm = phdr->p_flags;
        ef->load_instr[i].mem_offset = phdr->p_vaddr - ef->start_addr;
        ef->load_instr[i].file_offset = phdr->p_offset;
        ef->load_instr[i].memsz = phdr->p_memsz;
        ef->load_instr[i].filesz = phdr->p_filesz;
        ef->load_instr[i].virt_addr = phdr->p_vaddr;

        ef->num_load_instr++;
    }
}

static inline void
private_process_dynamic_section(struct bfelf_file_t *ef)
{
    bfelf64_xword i = 0;

    if (ef->dynnum == 0 || ef->dynoff == 0)
        return;

    ef->num_needed = 0;
    ef->dyntab = rcast(const struct bfelf_dyn *, ef->file + ef->dynoff);

    for (i = 0; i < ef->dynnum; i++)
    {
        const struct bfelf_dyn *dyn = &(ef->dyntab[i]);

        switch (dyn->d_tag)
        {
            case bfdt_null:
                return;

            case bfdt_needed:

                if (ef->num_needed < BFELF_MAX_NEEDED)
                {
                    ef->needed[ef->num_needed++] = dyn->d_val;
                }

                break;

            case bfdt_pltrelsz:
                ef->relanum_plt = dyn->d_val / sizeof(struct bfelf_rela);
                break;

            case bfdt_hash:
                ef->hash = rcast(bfelf64_word *, dyn->d_val);
                break;

            case bfdt_strtab:
                ef->strtab = rcast(char *, dyn->d_val);
                break;

            case bfdt_symtab:
                ef->symtab = rcast(struct bfelf_sym *, dyn->d_val);
                break;

            case bfdt_rela:
                ef->relatab_dyn = rcast(struct bfelf_rela *, dyn->d_val);
                break;

            case bfdt_relasz:
                ef->relanum_dyn = dyn->d_val / sizeof(struct bfelf_rela);
                break;

            case bfdt_init:
                ef->init = dyn->d_val;
                break;

            case bfdt_fini:
                ef->fini = dyn->d_val;
                break;

            case bfdt_jmprel:
                ef->relatab_plt = rcast(struct bfelf_rela *, dyn->d_val);
                break;

            case bfdt_init_array:
                ef->init_array = dyn->d_val;
                break;

            case bfdt_fini_array:
                ef->fini_array = dyn->d_val;
                break;

            case bfdt_init_arraysz:
                ef->init_arraysz = dyn->d_val;
                break;

            case bfdt_fini_arraysz:
                ef->fini_arraysz = dyn->d_val;
                break;

            case bfdt_flags_1:
                ef->flags_1 = dyn->d_val;
                break;

            default:
                break;
        }
    }
}

/* @endcond */

/**
 * Initialize an ELF file
 *
 * This function initializes an ELF file structure given the file's contents
 * in memory. The resulting structure will be used by all of the other
 * functions.
 *
 * @expects file != nullptr
 * @expects filesz != nullptr
 * @expects ef != nullptr
 * @ensures
 *
 * @param file a character buffer containing the contents of the ELF file to
 *     be loaded.
 * @param filesz the size of the character buffer
 * @param ef the ELF file structure to initialize.
 * @return BFELF_SUCCESS on success, negative on error
 */
static inline int64_t
bfelf_file_init(const char *file, uint64_t filesz, struct bfelf_file_t *ef)
{
    int64_t ret = 0;
    bfelf64_word i = 0;

    if (!file)
    {
        return bfinvalid_argument("file == NULL");
    }

    if (!ef)
    {
        return bfinvalid_argument("ef == NULL");
    }

    if (filesz == 0 || filesz < sizeof(struct bfelf_ehdr))
    {
        return bfinvalid_argument("filesz invalid");
    }

    for (i = 0; i < sizeof(struct bfelf_file_t); i++)
    {
        rcast(char *, ef)[i] = 0;
    }

    ef->file = file;
    ef->filesz = filesz;

    ef->ehdr = rcast(const struct bfelf_ehdr *, file);
    ef->phdrtab = rcast(const struct bfelf_phdr *, file + ef->ehdr->e_phoff);
    ef->shdrtab = rcast(const struct bfelf_shdr *, file + ef->ehdr->e_shoff);

    ret = private_check_signature(ef);
    if (ret != BFELF_SUCCESS)
    {
        goto failure;
    }

    ret = private_check_support(ef);
    if (ret != BFELF_SUCCESS)
    {
        goto failure;
    }

    private_process_segments(ef);
    private_process_dynamic_section(ef);

    ef->entry = ef->ehdr->e_entry;
    ef->shstrtab = rcast(const char *, file + ef->shdrtab[ef->ehdr->e_shstrndx].sh_offset);

    /*
     * ld from binutils 2.27 only has rela.dyn, while ld.gold and ld.lld both
     * have rela.dyn and rela.plt. ld from binutils 2.27 also uses
     * .init_array / .fini_array instead of .ctors / .dtors, while ld.gold and
     * ld.lld still use the old .ctors / .dtors, which do not seems to show
     * up in the .dynamic section, so we need to manually search for them.
     * Since you will likely only have one or the other, if we see the old
     * .ctors / .dtors, we treat it like .init_array / .fini_array for now
     * which keeps things simple. Also, ld from binutils 2.27 marks .eh_frame
     * with bfsht_x86_64_unwind, while ld.gold and ld.lld both mark .eh_frame
     * with bfsht_progbits, also requiring a manual string search.
     *
     * Note that the file provided in this function is assumed to be deleted
     * after this function is called, and thus, we have to search for these
     * sections now because the file will not be available later.
     */

    for (i = 0; i < ef->ehdr->e_shnum; i++)
    {
        const struct bfelf_shdr *shdr = &(ef->shdrtab[i]);
        const char *name = &ef->shstrtab[shdr->sh_name];

        if (private_strcmp(name, ".eh_frame") == BFELF_SUCCESS)
        {
            ef->eh_frame = shdr->sh_addr;
            ef->eh_framesz = shdr->sh_size;
            continue;
        }

        if (private_strcmp(name, ".ctors") == BFELF_SUCCESS)
        {
            ef->init_array = shdr->sh_addr;
            ef->init_arraysz = shdr->sh_size;
            continue;
        }

        if (private_strcmp(name, ".dtors") == BFELF_SUCCESS)
        {
            ef->fini_array = shdr->sh_addr;
            ef->fini_arraysz = shdr->sh_size;
            continue;
        }
    }

    return BFELF_SUCCESS;

failure:

    for (i = 0; i < sizeof(struct bfelf_file_t); i++)
    {
        rcast(char *, ef)[i] = 0;
    }

    return ret;
}

/**
 * Get number of load instructions
 *
 * Once an ELF file has been initialized, the next step is to load all of the
 * program segments into memory, relocate them, and then execute the entry
 * point. To assist this operation, this function returns the total number of
 * load instructions.
 *
 * @expects ef != nullptr
 * @ensures returns BFELF_SUCCESS if params == valid
 *
 * @param ef the ELF file
 * @return number of load instructions on success, negative on error
 */
static inline int64_t
bfelf_file_get_num_load_instrs(struct bfelf_file_t *ef)
{
    if (!ef)
    {
        return bfinvalid_argument("ef == NULL");
    }

    return scast(int64_t, ef->num_load_instr);
}

/**
 * Get load instructions
 *
 * Once you know how many load instructions there are, you can use this
 * function to get each instruction structure.
 *
 * @expects ef != nullptr
 * @expects index < bfelf_file_get_num_load_instrs()
 * @expects instr != nullptr
 * @ensures returns BFELF_SUCCESS if params == valid
 *
 * @param ef the ELF file
 * @param index the index of the instructions to get
 * @param instr where to store the load instructions
 * @return BFELF_SUCCESS on success, negative on error
 */
static inline int64_t
bfelf_file_get_load_instr(struct bfelf_file_t *ef, uint64_t index, struct bfelf_load_instr **instr)
{
    if (!ef)
    {
        return bfinvalid_argument("ef == NULL");
    }

    if (!instr)
    {
        return bfinvalid_argument("phdr == NULL");
    }

    if (index >= ef->num_load_instr)
    {
        return bfinvalid_index("index >= number of load instructions");
    }

    *instr = &(ef->load_instr[index]);
    return BFELF_SUCCESS;
}

/**
 * Get Info
 *
 * Once an ELF loader has had all of it's ELF files initialized and added,
 * use the relocate ELF loader to setup the ELF files such that they can
 * be executed. Once this is done, this function can be used to get the
 * C runtime information for bootstrapping a binary / module.
 *
 * @expects ef != nullptr
 * @expects info != nullptr
 * @ensures returns BFELF_SUCCESS if params == valid
 *
 * @param ef the ELF file to get the info structure for
 * @param info the info structure to store the results.
 * @return BFELF_SUCCESS on success, negative on error
 */
static inline int64_t
bfelf_file_get_section_info(struct bfelf_file_t *ef, struct section_info_t *info)
{
    bfelf64_word i = 0;

    if (!ef)
    {
        return bfinvalid_argument("ef == NULL");
    }

    if (!info)
    {
        return bfinvalid_argument("info == NULL");
    }

    for (i = 0; i < sizeof(struct section_info_t); i++)
    {
        rcast(char *, info)[i] = 0;
    }

    if (ef->init != 0)
    {
        info->init_addr = ef->init + ef->exec_virt;
    }

    if (ef->fini != 0)
    {
        info->fini_addr = ef->fini + ef->exec_virt;
    }

    if (ef->init_array != 0)
    {
        info->init_array_addr = ef->init_array + ef->exec_virt;
        info->init_array_size = ef->init_arraysz;
    }

    if (ef->fini_array != 0)
    {
        info->fini_array_addr = ef->fini_array + ef->exec_virt;
        info->fini_array_size = ef->fini_arraysz;
    }

    if (ef->eh_frame != 0)
    {
        info->eh_frame_addr = ef->eh_frame + ef->exec_virt;
        info->eh_frame_size = ef->eh_framesz;
    }

    return BFELF_SUCCESS;
}

/**
 * Get Entry Point
 *
 * Returns the entry point of the ELF file.
 *
 * @expects ef != nullptr
 * @expects addr != nullptr
 * @ensures returns BFELF_SUCCESS if params == valid
 *
 * @param ef the ELF file to get the info structure for
 * @param addr the resulting address of the entry point
 * @return BFELF_SUCCESS on success, negative on error
 */
static inline int64_t
bfelf_file_get_entry(struct bfelf_file_t *ef, void **addr)
{
    if (!ef)
    {
        return bfinvalid_argument("ef == NULL");
    }

    if (!addr)
    {
        return bfinvalid_argument("addr == NULL");
    }

    *addr = rcast(void *, ef->entry + ef->exec_virt);
    return BFELF_SUCCESS;
}

/**
 * Get Stack Permissions
 *
 * Returns the ELF file's stack permissions.
 *
 * @expects ef != nullptr
 * @expects perm != nullptr
 * @ensures returns BFELF_SUCCESS if params == valid
 *
 * @param ef the ELF file to get the info structure for
 * @param perm the resulting permissions
 * @return BFELF_SUCCESS on success, negative on error
 */
static inline int64_t
bfelf_file_get_stack_perm(struct bfelf_file_t *ef, bfelf64_xword *perm)
{
    if (!ef)
    {
        return bfinvalid_argument("ef == NULL");
    }

    if (!perm)
    {
        return bfinvalid_argument("perm == NULL");
    }

    *perm = ef->stack_flags;
    return BFELF_SUCCESS;
}

/**
 * Get Relocation Read-Only Info
 *
 * Returns the ELF file's RELRO information for
 * re-mapping previously writable memory to read-only
 *
 * @expects ef != nullptr
 * @expects addr != nullptr
 * @expects size != nullptr
 * @ensures returns BFELF_SUCCESS if params == valid
 *
 * @param ef the ELF file to get the info structure for
 * @param addr the resulting address
 * @param size the resulting size
 * @return BFELF_SUCCESS on success, negative on error
 */
static inline int64_t
bfelf_file_get_relro(struct bfelf_file_t *ef, bfelf64_addr *addr, bfelf64_xword *size)
{
    if (!ef)
    {
        return bfinvalid_argument("ef == NULL");
    }

    if (!addr)
    {
        return bfinvalid_argument("addr == NULL");
    }

    if (!size)
    {
        return bfinvalid_argument("size == NULL");
    }

    *addr = ef->relaro_vaddr + rcast(bfelf64_addr, ef->exec_virt);
    *size = ef->relaro_memsz;
    return BFELF_SUCCESS;
}

/**
 * Get Number of Needed Libraries
 *
 * Returns the number of DT_NEEDED entries in the ELF
 * file
 *
 * @expects ef != nullptr
 * @ensures returns BFELF_SUCCESS if params == valid
 *
 * @param ef the ELF file to get the info structure for
 * @return number of needed entries on success, negative on error
 */
static inline int64_t
bfelf_file_get_num_needed(struct bfelf_file_t *ef)
{
    if (!ef)
    {
        return bfinvalid_argument("ef == NULL");
    }

    return scast(int64_t, ef->num_needed);
}

/**
 * Get Needed Library
 *
 * Returns the name of a shared library that is needed by this
 * ELF file
 *
 * @expects ef != nullptr
 * @expects index < bfelf_file_get_num_needed()
 * @expects needed != nullptr
 * @ensures returns BFELF_SUCCESS if params == valid
 *
 * @param ef the ELF file to get the info structure for
 * @param index the shared library name to get
 * @param needed the resulting needed library
 * @return number of needed entries on success, negative on error
 */
static inline int64_t
bfelf_file_get_needed(struct bfelf_file_t *ef, uint64_t index, const char **needed)
{
    if (!ef)
    {
        return bfinvalid_argument("ef == NULL");
    }

    if (!needed)
    {
        return bfinvalid_argument("needed == NULL");
    }

    if (index >= ef->num_needed)
    {
        return bfinvalid_index("index >= number of needed");
    }

    *needed = &(ef->strtab[ef->needed[index]]);
    return BFELF_SUCCESS;
}

/**
 * Get Total Memory Size
 *
 * Returns the total number of bytes needed in memory for this ELF file
 * when loading the ELF file
 *
 * @expects ef != nullptr
 * @ensures returns BFELF_SUCCESS if params == valid
 *
 * @param ef the ELF file to get the info structure for
 * @return number of needed entries on success, negative on error
 */
static inline int64_t
bfelf_file_get_total_size(struct bfelf_file_t *ef)
{
    if (!ef)
    {
        return bfinvalid_argument("ef == NULL");
    }

    return scast(int64_t, ef->total_memsz);
}

/**
 * Get PIC/PIE
 *
 * Returns 1 if this ELF file was compiled using PIC / PIE, or
 * 0 otherwise
 *
 * @expects ef != nullptr
 * @ensures returns BFELF_SUCCESS if params == valid
 *
 * @param ef the ELF file to get the info structure for
 * @return 1 if compiled with PIC/PIE, 0 otherwise
 */
static inline int64_t
bfelf_file_get_pic_pie(struct bfelf_file_t *ef)
{
    if (!ef)
    {
        return bfinvalid_argument("ef == NULL");
    }

    return ef->start_addr == 0 ? 1 : 0;
}

/* ---------------------------------------------------------------------------------------------- */
/* ELF Loader Implementation                                                                      */
/* ---------------------------------------------------------------------------------------------- */

/**
 * Add ELF file to an ELF loader
 *
 * Once an ELF loader has been initialized, use this function to add an
 * ELF file to the ELF loader
 *
 * @expects loader != nullptr
 * @expects ef != nullptr
 * @expects exec_addr != nullptr
 * @expects exec_virt != nullptr
 * @ensures
 *
 * @param loader the ELF loader
 * @param ef the ELF file to add
 * @param exec_addr the address in memory where this ELF file was loaded.
 * @param exec_virt the address in memory where this ELF file will be run.
 * @return BFELF_SUCCESS on success, negative on error
 */
static inline int64_t
bfelf_loader_add(
    struct bfelf_loader_t *loader, struct bfelf_file_t *ef, char *exec_addr, char *exec_virt)
{
    bfelf64_addr start;

    if (!loader)
    {
        return bfinvalid_argument("loader == NULL");
    }

    if (!ef)
    {
        return bfinvalid_argument("ef == NULL");
    }

    if (!exec_addr)
    {
        return bfinvalid_argument("exec_addr == NULL");
    }

    if (loader->num >= MAX_NUM_MODULES)
    {
        return bfloader_full("increase MAX_NUM_MODULES");
    }

    if (ef->added++ != 0)
    {
        return bfinvalid_argument("ef already added");
    }

    ef->exec_addr = exec_addr;

    if (ef->start_addr == 0)
    {
        ef->exec_virt = exec_virt;
    }

    start = rcast(bfelf64_addr, ef->exec_addr - ef->start_addr);

    ef->hash = add(const bfelf64_word *, ef->hash, start);
    ef->strtab = add(const char *, ef->strtab, start);
    ef->symtab = add(const struct bfelf_sym *, ef->symtab, start);
    ef->relatab_dyn = add(const struct bfelf_rela *, ef->relatab_dyn, start);
    ef->relatab_plt = add(const struct bfelf_rela *, ef->relatab_plt, start);

    ef->nbucket = ef->hash[0];
    ef->nchain = ef->hash[1];
    ef->bucket = &(ef->hash[2]);
    ef->chain = &(ef->hash[2 + ef->nbucket]);

    /*
     * Sadly, the only way to determine the total size of the dynamic symbol
     * table is to assume that the dynamic string table is always after the
     * dynamic symbol table. :(
     */
    ef->symnum = (rcast(bfelf64_addr, ef->strtab) - rcast(bfelf64_addr, ef->symtab)) /
                 sizeof(struct bfelf_sym);

    loader->efs[loader->num++] = ef;
    return BFELF_SUCCESS;
}

/**
 * Relocate ELF Loader
 *
 * Relocates all of the ELF files that have been added to the ELF loader.
 * Once all of the ELF files have been relocated, it's safe to resolve
 * symbols for execution.
 *
 * @expects loader != nullptr
 * @ensures
 *
 * @param loader the ELF loader
 * @return BFELF_SUCCESS on success, negative on error
 */
static inline int64_t
bfelf_loader_relocate(struct bfelf_loader_t *loader)
{
    int64_t ret = 0;
    bfelf64_word i = 0;

    if (!loader)
    {
        return bfinvalid_argument("loader == NULL");
    }

    if (loader->relocated == 1)
    {
        return BFELF_SUCCESS;
    }

    for (i = 0; i < loader->num; i++)
    {
        ret = private_relocate_symbols(loader, loader->efs[i]);
        if (ret != BFELF_SUCCESS)
        {
            return ret;
        }
    }

    loader->relocated = 1;
    return BFELF_SUCCESS;
}

/**
 * Resolve Symbol
 *
 * Once an ELF loader has had all of it's ELF files initialized and added,
 * use the relocate ELF loader to setup the ELF files such that they can
 * be executed. If the ELF file is relocated into memory that is accessible
 * via the ELF loader, the resolve symbol function can be used to get the
 * address of a specific symbol so that it can be executed.
 *
 * @expects loader != nullptr
 * @expects loader != name
 * @expects loader != addr
 * @ensures
 *
 * @param loader the ELF loader
 * @param name the name of the symbol to resolve
 * @param addr the resulting address if the symbol is successfully resolved
 * @return BFELF_SUCCESS on success, negative on error
 */
static inline int64_t
bfelf_loader_resolve_symbol(struct bfelf_loader_t *loader, const char *name, void **addr)
{
    int64_t ret = 0;

    struct bfelf_file_t *found_ef = 0;
    const struct bfelf_sym *found_sym = 0;

    if (!loader)
    {
        return bfinvalid_argument("loader == NULL");
    }

    if (!name)
    {
        return bfinvalid_argument("name == NULL");
    }

    if (!addr)
    {
        return bfinvalid_argument("addr == NULL");
    }

    ret = private_get_sym_global(loader, name, &found_ef, &found_sym);
    if (ret != BFELF_SUCCESS)
    {
        return ret;
    }

    *addr = found_ef->exec_virt + found_sym->st_value;
    return BFELF_SUCCESS;
}

#ifdef __cplusplus
}
#endif

#pragma pack(pop)
#endif
