/*
 * Copyright (C) 2019 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/**
 * @file bfelf_loader.h
 */

#ifndef BFELF_LOADER_H
#define BFELF_LOADER_H

#include <bftypes.h>
#include <bfdebug.h>
#include <bfsupport.h>
#include <bfplatform.h>
#include <bfconstants.h>
#include <bferrorcodes.h>
#include <bfarch.h>

#pragma pack(push, 1)

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

#ifndef __cplusplus
typedef uint64_t bfelf64_addr;
typedef uint64_t bfelf64_off;
typedef uint16_t bfelf64_half;
typedef uint32_t bfelf64_word;
typedef int32_t bfelf64_sword;
typedef uint64_t bfelf64_xword;
typedef int64_t bfelf64_sxword;
#else
using bfelf64_addr = uint64_t;
using bfelf64_off = uint64_t;
using bfelf64_half = uint16_t;
using bfelf64_word = uint32_t;
using bfelf64_sword = int32_t;
using bfelf64_xword = uint64_t;
using bfelf64_sxword = int64_t;
#endif

/* @endcond */

/* ---------------------------------------------------------------------------------------------- */
/* ELF Error Codes                                                                                */
/* ---------------------------------------------------------------------------------------------- */

/* @cond */

static inline int64_t
private_error(const char *header, const char *msg, const char *func, int line, int64_t code)
{
    BFALERT("%s [%d] %s: %s\n", func, line, header, msg);
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

#define bfout_of_memory(a)                                                                         \
    private_error("out of memory", a, __func__, __LINE__, BFELF_ERROR_OUT_OF_MEMORY);

/* @endcond */

/* ---------------------------------------------------------------------------------------------- */
/* ELF Helpers                                                                                    */
/* ---------------------------------------------------------------------------------------------- */

/* @cond */

static inline int64_t
private_strcmp(const char *s1, const char *s2)
{
    while ((*s1 != 0) && (*s1 == *s2)) {
        s1++, s2++;
    }

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
 * - map memory using the phys_addr and mem_size
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
 * @var bfelf_load_instr::phys_addr
 *      defines the assumed virtual address of the segment if PIC == false
 */
struct bfelf_load_instr {
    bfelf64_word perm;
    bfelf64_off mem_offset;
    bfelf64_off file_offset;
    bfelf64_xword memsz;
    bfelf64_xword filesz;
    bfelf64_addr phys_addr;
};

/*
 * ELF File
 *
 * The following is used by this API to store information about the ELF file
 * being used.
 *
 * @cond
 */
struct bfelf_file_t {
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
    const struct bfelf_shdr *notes;

    bfelf64_addr dynoff;

    const char *strtab;
    const char *strtab_offset;
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
#define bfei_mag0 bfscast(bfelf64_sword, 0)
#define bfei_mag1 bfscast(bfelf64_sword, 1)
#define bfei_mag2 bfscast(bfelf64_sword, 2)
#define bfei_mag3 bfscast(bfelf64_sword, 3)
#define bfei_class bfscast(bfelf64_sword, 4)
#define bfei_data bfscast(bfelf64_sword, 5)
#define bfei_version bfscast(bfelf64_sword, 6)
#define bfei_osabi bfscast(bfelf64_sword, 7)
#define bfei_abiversion bfscast(bfelf64_sword, 8)
#define bfei_pad bfscast(bfelf64_sword, 9)
#define bfei_nident bfscast(bfelf64_sword, 16)

/* @endcond */

/*
 * ELF Class Types
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 5
 *
 * @cond
 */
#define bfelfclass32 bfscast(unsigned char, 1)
#define bfelfclass64 bfscast(unsigned char, 2)

/* @endcond */

/*
 * ELF Data Types
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 5
 *
 * @cond
 */
#define bfelfdata2lsb bfscast(unsigned char, 1)
#define bfelfdata2msb bfscast(unsigned char, 2)

/* @endcond */

/*
 * ELF Version
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 4
 *
 * @cond
 */
#define bfev_current bfscast(unsigned char, 1)

/* @endcond */

/*
 * ELF OS / ABI Types
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 5
 *
 * @cond
 */
#define bfelfosabi_sysv bfscast(unsigned char, 0)
#define bfelfosabi_hpux bfscast(unsigned char, 1)
#define bfelfosabi_standalone bfscast(unsigned char, 255)

/* @endcond */

/*
 * ELF Types
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 5
 *
 * @cond
 */
#define bfet_none bfscast(bfelf64_half, 0)
#define bfet_rel bfscast(bfelf64_half, 1)
#define bfet_exec bfscast(bfelf64_half, 2)
#define bfet_dyn bfscast(bfelf64_half, 3)
#define bfet_core bfscast(bfelf64_half, 4)
#define bfet_loos bfscast(bfelf64_half, 0xFE00)
#define bfet_hios bfscast(bfelf64_half, 0xFEFF)
#define bfet_loproc bfscast(bfelf64_half, 0xFF00)
#define bfet_hiproc bfscast(bfelf64_half, 0xFFFF)

/* @endcond */

/*
 * ELF Machine Codes
 *
 * The following is defined in the Linux kernel sources:
 * linux/include/uapi/linux/elf-em.h
 *
 * @cond
 */
#define bfem_none bfscast(bfelf64_half, 0)
#define bfem_m32 bfscast(bfelf64_half, 1)
#define bfem_sparc bfscast(bfelf64_half, 2)
#define bfem_386 bfscast(bfelf64_half, 3)
#define bfem_68k bfscast(bfelf64_half, 4)
#define bfem_88k bfscast(bfelf64_half, 5)
#define bfem_486 bfscast(bfelf64_half, 6)
#define bfem_860 bfscast(bfelf64_half, 7)
#define bfem_mips bfscast(bfelf64_half, 8)
#define bfem_mips_rs3_le bfscast(bfelf64_half, 10)
#define bfem_mips_rs4_be bfscast(bfelf64_half, 11)
#define bfem_parisc bfscast(bfelf64_half, 15)
#define bfem_sparc32plus bfscast(bfelf64_half, 18)
#define bfem_ppc bfscast(bfelf64_half, 20)
#define bfem_ppc64 bfscast(bfelf64_half, 21)
#define bfem_spu bfscast(bfelf64_half, 23)
#define bfem_arm bfscast(bfelf64_half, 40)
#define bfem_sh bfscast(bfelf64_half, 42)
#define bfem_sparcv9 bfscast(bfelf64_half, 43)
#define bfem_h8_300 bfscast(bfelf64_half, 46)
#define bfem_ia_64 bfscast(bfelf64_half, 50)
#define bfem_x86_64 bfscast(bfelf64_half, 62)
#define bfem_s390 bfscast(bfelf64_half, 22)
#define bfem_cris bfscast(bfelf64_half, 76)
#define bfem_v850 bfscast(bfelf64_half, 87)
#define bfem_m32r bfscast(bfelf64_half, 88)
#define bfem_mn10300 bfscast(bfelf64_half, 89)
#define bfem_openrisc bfscast(bfelf64_half, 92)
#define bfem_blackfin bfscast(bfelf64_half, 106)
#define bfem_altera_nios2 bfscast(bfelf64_half, 113)
#define bfem_ti_c6000 bfscast(bfelf64_half, 140)
#define bfem_aarch64 bfscast(bfelf64_half, 183)
#define bfem_frv bfscast(bfelf64_half, 0x5441)
#define bfem_avr32 bfscast(bfelf64_half, 0x18AD)
#define bfem_alpha bfscast(bfelf64_half, 0x9026)
#define bfem_cygnus_v850 bfscast(bfelf64_half, 0x9080)
#define bfem_cygnus_m32r bfscast(bfelf64_half, 0x9041)
#define bfem_s390_old bfscast(bfelf64_half, 0xA390)
#define bfem_cygnus_mn10300 bfscast(bfelf64_half, 0xBEEF)

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
struct bfelf_ehdr {
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
#define bfsht_null bfscast(bfelf64_word, 0)
#define bfsht_progbits bfscast(bfelf64_word, 1)
#define bfsht_symtab bfscast(bfelf64_word, 2)
#define bfsht_strtab bfscast(bfelf64_word, 3)
#define bfsht_rela bfscast(bfelf64_word, 4)
#define bfsht_hash bfscast(bfelf64_word, 5)
#define bfsht_dynamic bfscast(bfelf64_word, 6)
#define bfsht_note bfscast(bfelf64_word, 7)
#define bfsht_nobits bfscast(bfelf64_word, 8)
#define bfsht_rel bfscast(bfelf64_word, 9)
#define bfsht_shlib bfscast(bfelf64_word, 10)
#define bfsht_dynsym bfscast(bfelf64_word, 11)
#define bfsht_init_array bfscast(bfelf64_word, 14)
#define bfsht_fini_array bfscast(bfelf64_word, 15)
#define bfsht_loos bfscast(bfelf64_word, 0x60000000)
#define bfsht_hios bfscast(bfelf64_word, 0x6FFFFFFF)
#define bfsht_loproc bfscast(bfelf64_word, 0x70000000)
#define bfsht_x86_64_unwind bfscast(bfelf64_word, 0x70000001)
#define bfsht_hiproc bfscast(bfelf64_word, 0x7FFFFFFF)

/* @endcond */

/*
 * ELF Section Attributes
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 8
 *
 * @cond
 */
#define bfshf_write bfscast(bfelf64_xword, 0x1)
#define bfshf_alloc bfscast(bfelf64_xword, 0x2)
#define bfshf_execinstr bfscast(bfelf64_xword, 0x4)
#define bfshf_maskos bfscast(bfelf64_xword, 0x0F000000)
#define bfshf_maskproc bfscast(bfelf64_xword, 0xF0000000)
#define bfshf_undocumneted bfscast(bfelf64_xword, 0x00000060)

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
struct bfelf_shdr {
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
#define bfdt_null bfscast(bfelf64_xword, 0)
#define bfdt_needed bfscast(bfelf64_xword, 1)
#define bfdt_pltrelsz bfscast(bfelf64_xword, 2)
#define bfdt_pltgot bfscast(bfelf64_xword, 3)
#define bfdt_hash bfscast(bfelf64_xword, 4)
#define bfdt_strtab bfscast(bfelf64_xword, 5)
#define bfdt_symtab bfscast(bfelf64_xword, 6)
#define bfdt_rela bfscast(bfelf64_xword, 7)
#define bfdt_relasz bfscast(bfelf64_xword, 8)
#define bfdt_relaent bfscast(bfelf64_xword, 9)
#define bfdt_strsz bfscast(bfelf64_xword, 10)
#define bfdt_syment bfscast(bfelf64_xword, 11)
#define bfdt_init bfscast(bfelf64_xword, 12)
#define bfdt_fini bfscast(bfelf64_xword, 13)
#define bfdt_soname bfscast(bfelf64_xword, 14)
#define bfdt_rpath bfscast(bfelf64_xword, 15)
#define bfdt_symbolic bfscast(bfelf64_xword, 16)
#define bfdt_rel bfscast(bfelf64_xword, 17)
#define bfdt_relsz bfscast(bfelf64_xword, 18)
#define bfdt_relent bfscast(bfelf64_xword, 19)
#define bfdt_pltrel bfscast(bfelf64_xword, 20)
#define bfdt_debug bfscast(bfelf64_xword, 21)
#define bfdt_textrel bfscast(bfelf64_xword, 22)
#define bfdt_jmprel bfscast(bfelf64_xword, 23)
#define bfdt_bind_now bfscast(bfelf64_xword, 24)
#define bfdt_init_array bfscast(bfelf64_xword, 25)
#define bfdt_fini_array bfscast(bfelf64_xword, 26)
#define bfdt_init_arraysz bfscast(bfelf64_xword, 27)
#define bfdt_fini_arraysz bfscast(bfelf64_xword, 28)
#define bfdt_loos bfscast(bfelf64_xword, 0x60000000)
#define bfdt_relacount bfscast(bfelf64_xword, 0x6ffffff9)
#define bfdt_relcount bfscast(bfelf64_xword, 0x6ffffffa)
#define bfdt_flags_1 bfscast(bfelf64_xword, 0x6ffffffb)
#define bfdt_hios bfscast(bfelf64_xword, 0x6FFFFFFF)
#define bfdt_loproc bfscast(bfelf64_xword, 0x70000000)
#define bfdt_hiproc bfscast(bfelf64_xword, 0x7FFFFFFF)

#define bfdf_1_now bfscast(bfelf64_xword, 0x00000001)
#define bfdf_1_global bfscast(bfelf64_xword, 0x00000002)
#define bfdf_1_group bfscast(bfelf64_xword, 0x00000004)
#define bfdf_1_nodelete bfscast(bfelf64_xword, 0x00000008)
#define bfdf_1_loadfltr bfscast(bfelf64_xword, 0x00000010)
#define bfdf_1_initfirst bfscast(bfelf64_xword, 0x00000020)
#define bfdf_1_noopen bfscast(bfelf64_xword, 0x00000040)
#define bfdf_1_origin bfscast(bfelf64_xword, 0x00000080)
#define bfdf_1_direct bfscast(bfelf64_xword, 0x00000100)
#define bfdf_1_trans bfscast(bfelf64_xword, 0x00000200)
#define bfdf_1_interpose bfscast(bfelf64_xword, 0x00000400)
#define bfdf_1_nodeflib bfscast(bfelf64_xword, 0x00000800)
#define bfdf_1_nodump bfscast(bfelf64_xword, 0x00001000)
#define bfdf_1_confalt bfscast(bfelf64_xword, 0x00002000)
#define bfdf_1_endfiltee bfscast(bfelf64_xword, 0x00004000)
#define bfdf_1_dispreldne bfscast(bfelf64_xword, 0x00008000)
#define bfdf_1_disprelpnd bfscast(bfelf64_xword, 0x00010000)
#define bfdf_1_nodirect bfscast(bfelf64_xword, 0x00020000)
#define bfdf_1_ignmuldef bfscast(bfelf64_xword, 0x00040000)
#define bfdf_1_noksyms bfscast(bfelf64_xword, 0x00080000)
#define bfdf_1_nohdr bfscast(bfelf64_xword, 0x00100000)
#define bfdf_1_edited bfscast(bfelf64_xword, 0x00200000)
#define bfdf_1_noreloc bfscast(bfelf64_xword, 0x00400000)
#define bfdf_1_symintpose bfscast(bfelf64_xword, 0x00800000)
#define bfdf_1_globaudit bfscast(bfelf64_xword, 0x01000000)
#define bfdf_1_singleton bfscast(bfelf64_xword, 0x02000000)
#define bfdf_1_pie bfscast(bfelf64_xword, 0x08000000)

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
struct bfelf_dyn {
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
#define bfstb_local bfscast(unsigned char, 0)
#define bfstb_global bfscast(unsigned char, 1)
#define bfstb_weak bfscast(unsigned char, 2)
#define bfstb_loos bfscast(unsigned char, 10)
#define bfstb_hios bfscast(unsigned char, 12)
#define bfstb_loproc bfscast(unsigned char, 13)
#define bfstb_hiproc bfscast(unsigned char, 15)

/* @endcond */

/*
 * ELF Symbol Types
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 10
 *
 * @cond
 */
#define bfstt_notype bfscast(unsigned char, 0)
#define bfstt_object bfscast(unsigned char, 1)
#define bfstt_func bfscast(unsigned char, 2)
#define bfstt_section bfscast(unsigned char, 3)
#define bfstt_file bfscast(unsigned char, 4)
#define bfstt_loos bfscast(unsigned char, 10)
#define bfstt_hios bfscast(unsigned char, 12)
#define bfstt_loproc bfscast(unsigned char, 13)
#define bfstt_hiproc bfscast(unsigned char, 15)

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
struct bfelf_sym {
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
 * ELF Relocation
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 11
 *
 * @cond
 */
struct bfelf_rel {
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
struct bfelf_rela {
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
#define bfpt_null bfscast(bfelf64_word, 0)
#define bfpt_load bfscast(bfelf64_word, 1)
#define bfpt_dynamic bfscast(bfelf64_word, 2)
#define bfpt_interp bfscast(bfelf64_word, 3)
#define bfpt_note bfscast(bfelf64_word, 4)
#define bfpt_shlib bfscast(bfelf64_word, 5)
#define bfpt_phdr bfscast(bfelf64_word, 6)
#define bfpt_loos bfscast(bfelf64_word, 0x60000000)
#define bfpt_gnu_eh_frame bfscast(bfelf64_word, 0x6474e550)
#define bfpt_gnu_stack bfscast(bfelf64_word, 0x6474e551)
#define bfpt_gnu_relro bfscast(bfelf64_word, 0x6474e552)
#define bfpt_hios bfscast(bfelf64_word, 0x6FFFFFFF)
#define bfpt_loproc bfscast(bfelf64_word, 0x70000000)
#define bfpt_hiproc bfscast(bfelf64_word, 0x7FFFFFFF)

/* @endcond */

/*
 * ELF Section Attributes
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 13
 *
 * @cond
 */
#define bfpf_x bfscast(bfelf64_xword, 0x1)
#define bfpf_w bfscast(bfelf64_xword, 0x2)
#define bfpf_r bfscast(bfelf64_xword, 0x4)
#define bfpf_maskos bfscast(bfelf64_xword, 0x00FF0000)
#define bfpf_maskproc bfscast(bfelf64_xword, 0xFF000000)

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
struct bfelf_phdr {
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
struct bfelf_loader_t {
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
    unsigned long h = 0;

    while (*name != 0) {
        char c = *name++;
        unsigned long g;
        unsigned char uc = bfscast(unsigned char, c);

        if (c >= 0) {
            h = (h << 4) + uc;
        }
        else {
            h = (h << 4) - uc;
        }

        if ((g = (h & 0xf0000000)) != 0) {
            h ^= g >> 24;
        }

        h &= 0x0fffffff;
    }

    return h;
}

static inline int64_t
private_get_sym_by_hash(
    struct bfelf_file_t *ef, const char *name, const struct bfelf_sym **sym)
{
    bfelf64_word i = 0;
    unsigned long x = private_hash(name);

    i = ef->bucket[x % ef->nbucket];
    while (i > STN_UNDEF && i < ef->nchain) {
        int64_t ret = 0;
        const char *str = nullptr;

        *sym = &(ef->symtab[i]);
        str = &(ef->strtab[(*sym)->st_name]);

        ret = private_strcmp(name, str);
        if (ret == BFELF_ERROR_MISMATCH) {
            i = ef->chain[i];
            continue;
        }

        return BFELF_SUCCESS;
    }

    return BFELF_ERROR_NO_SUCH_SYMBOL;
}

static inline int64_t
private_get_sym_by_name(
    struct bfelf_file_t *ef, const char *name, const struct bfelf_sym **sym)
{
    bfelf64_word i = 0;

    if (ef->hash != nullptr) {
        return private_get_sym_by_hash(ef, name, sym);
    }

    for (i = 0; i < ef->symnum; i++) {
        int64_t ret = 0;
        const char *str = nullptr;

        *sym = &(ef->symtab[i]);
        str = &(ef->strtab[(*sym)->st_name]);

        ret = private_strcmp(name, str);
        if (ret == BFELF_ERROR_MISMATCH) {
            continue;
        }

        return BFELF_SUCCESS;
    }

    return BFELF_ERROR_NO_SUCH_SYMBOL;
}

static inline int64_t
private_get_sym_global(
    const struct bfelf_loader_t *loader, const char *name,
    struct bfelf_file_t **ef_found, const struct bfelf_sym **sym)
{
    int64_t ret = 0;
    bfelf64_word i = 0;
    struct bfelf_file_t *ef_ignore = *ef_found;
    const struct bfelf_sym *found_sym = nullptr;

    *sym = nullptr;
    *ef_found = nullptr;

    for (i = 0; i < loader->num; i++) {
        if (loader->efs[i] == ef_ignore) {
            continue;
        }

        ret = private_get_sym_by_name(loader->efs[i], name, &found_sym);
        if (ret == BFELF_ERROR_NO_SUCH_SYMBOL) {
            continue;
        }

        if (found_sym->st_value == 0) {
            continue;
        }

        *sym = found_sym;
        *ef_found = loader->efs[i];

        if (BFELF_SYM_BIND(found_sym->st_info) == bfstb_weak) {
            continue;
        }

        return BFELF_SUCCESS;
    }

    if (*sym != nullptr) {
        return BFELF_SUCCESS;
    }

    return bfno_such_symbol(name);
}

/* @endcond */

/* ---------------------------------------------------------------------------------------------- */
/* ELF Relocations Implementation                                                                 */
/* ---------------------------------------------------------------------------------------------- */

/*
 * Forward declarations required by relocator
 *
 * @cond
 */

static inline int64_t
private_get_sym_global(
    const struct bfelf_loader_t *loader, const char *name,
    struct bfelf_file_t **ef_found, const struct bfelf_sym **sym);

/* @endcond */

/*
 * Relocation definitions and relocators
 *
 * @cond
 */

#if defined(BF_AARCH64)
#   include <bfelf_loader_reloc_aarch64.h>
#elif defined(BF_X64)
#   include <bfelf_loader_reloc_x64.h>
#else
#   error "Unsupported architecture"
#endif

/* @endcond */

/* @cond */

static inline int64_t
private_relocate_symbols(struct bfelf_loader_t *loader, struct bfelf_file_t *ef)
{
    int64_t ret = 0;
    bfelf64_word i = 0;

    for (i = 0; i < ef->relanum_dyn; i++) {
        const struct bfelf_rela *rela = &(ef->relatab_dyn[i]);

        ret = private_relocate_symbol(loader, ef, rela);
        if (ret != BFELF_SUCCESS) {
            return ret;
        }
    }

    for (i = 0; i < ef->relanum_plt; i++) {
        const struct bfelf_rela *rela = &(ef->relatab_plt[i]);

        ret = private_relocate_symbol(loader, ef, rela);
        if (ret != BFELF_SUCCESS) {
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
    if (ef->ehdr->e_ident[bfei_mag0] != 0x7F) {
        return bfinvalid_signature("magic #0 has unexpected value");
    }

    if (ef->ehdr->e_ident[bfei_mag1] != 'E') {
        return bfinvalid_signature("magic #1 has unexpected value");
    }

    if (ef->ehdr->e_ident[bfei_mag2] != 'L') {
        return bfinvalid_signature("magic #2 has unexpected value");
    }

    if (ef->ehdr->e_ident[bfei_mag3] != 'F') {
        return bfinvalid_signature("magic #3 has unexpected value");
    }

    return BFELF_SUCCESS;
}

static inline int64_t
private_check_support(struct bfelf_file_t *ef)
{
    if (ef->ehdr->e_ident[bfei_class] != bfelfclass64) {
        return bfunsupported_file("file is not 64bit");
    }

    if (ef->ehdr->e_ident[bfei_data] != bfelfdata2lsb) {
        return bfunsupported_file("file is not little endian");
    }

    if (ef->ehdr->e_ident[bfei_version] != bfev_current) {
        return bfunsupported_file("unsupported version");
    }

    if (ef->ehdr->e_ident[bfei_osabi] != bfelfosabi_sysv) {
        return bfunsupported_file("file does not use the system v abi");
    }

    if (ef->ehdr->e_ident[bfei_abiversion] != 0) {
        return bfunsupported_file("unsupported abi version");
    }

    if (ef->ehdr->e_type != bfet_dyn && ef->ehdr->e_type != bfet_exec) {
        return bfunsupported_file("file must be an executable or shared library");
    }

#ifdef BF_AARCH64
    if (ef->ehdr->e_machine != bfem_aarch64) {
        return bfunsupported_file("file must be compiled for aarch64");
    }
#endif

#ifdef BF_X64
    if (ef->ehdr->e_machine != bfem_x86_64) {
        return bfunsupported_file("file must be compiled for x86_64");
    }
#endif

    if (ef->ehdr->e_version != bfev_current) {
        return bfunsupported_file("unsupported version");
    }

    if (ef->ehdr->e_flags != 0) {
        return bfunsupported_file("unsupported flags");
    }

    return BFELF_SUCCESS;
}

static inline void
private_process_segments(struct bfelf_file_t *ef)
{
    bfelf64_xword i = 0;

    for (i = 0; i < ef->ehdr->e_phnum; i++) {
        const struct bfelf_phdr *phdr = &(ef->phdrtab[i]);

        switch (phdr->p_type) {
            case bfpt_load:

                if (ef->num_loadable_segments < BFELF_MAX_SEGMENTS) {
                    ef->total_memsz = phdr->p_paddr + phdr->p_memsz;
                    ef->loadable_segments[ef->num_loadable_segments++] = phdr;
                }

                break;

            case bfpt_dynamic:
                ef->dynoff = phdr->p_offset;
                ef->dynnum = phdr->p_filesz / sizeof(struct bfelf_dyn);
                break;
        }
    }

    if (ef->num_loadable_segments > 0) {
        ef->start_addr = ef->loadable_segments[0]->p_paddr;
        ef->total_memsz -= ef->start_addr;
    }

    for (i = 0; i < ef->num_loadable_segments; i++) {
        const struct bfelf_phdr *phdr = ef->loadable_segments[i];

        ef->load_instr[i].perm = phdr->p_flags;
        ef->load_instr[i].mem_offset = phdr->p_paddr - ef->start_addr;
        ef->load_instr[i].file_offset = phdr->p_offset;
        ef->load_instr[i].memsz = phdr->p_memsz;
        ef->load_instr[i].filesz = phdr->p_filesz;
        ef->load_instr[i].phys_addr = phdr->p_paddr;

        ef->num_load_instr++;
    }
}

static inline void
private_process_dynamic_section(struct bfelf_file_t *ef)
{
    bfelf64_xword i = 0;

    if (ef->dynnum == 0 || ef->dynoff == 0) {
        return;
    }

    ef->num_needed = 0;
    ef->dyntab = bfrcast(const struct bfelf_dyn *, ef->file + ef->dynoff);

    for (i = 0; i < ef->dynnum; i++) {
        const struct bfelf_dyn *dyn = &(ef->dyntab[i]);

        switch (dyn->d_tag) {
            case bfdt_null:
                return;

            case bfdt_needed:

                if (ef->num_needed < BFELF_MAX_NEEDED) {
                    ef->needed[ef->num_needed++] = dyn->d_val;
                }

                break;

            case bfdt_pltrelsz:
                ef->relanum_plt = dyn->d_val / sizeof(struct bfelf_rela);
                break;

            case bfdt_hash:
                ef->hash = bfrcast(bfelf64_word *, dyn->d_val);
                break;

            case bfdt_strtab:
                ef->strtab_offset = bfrcast(char *, dyn->d_val);
                break;

            case bfdt_symtab:
                ef->symtab = bfrcast(struct bfelf_sym *, dyn->d_val);
                break;

            case bfdt_rela:
                ef->relatab_dyn = bfrcast(struct bfelf_rela *, dyn->d_val);
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
                ef->relatab_plt = bfrcast(struct bfelf_rela *, dyn->d_val);
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

    if (file == nullptr) {
        return bfinvalid_argument("file == nullptr");
    }

    if (ef == nullptr) {
        return bfinvalid_argument("ef == nullptr");
    }

    if (filesz < sizeof(struct bfelf_ehdr)) {
        return bfinvalid_argument("filesz invalid");
    }

    ef->file = file;
    ef->filesz = filesz;

    ef->ehdr = bfrcast(const struct bfelf_ehdr *, file);
    ef->phdrtab = bfrcast(const struct bfelf_phdr *, file + ef->ehdr->e_phoff);
    ef->shdrtab = bfrcast(const struct bfelf_shdr *, file + ef->ehdr->e_shoff);

    ret = private_check_signature(ef);
    if (ret != BFELF_SUCCESS) {
        return ret;
    }

    ret = private_check_support(ef);
    if (ret != BFELF_SUCCESS) {
        return ret;
    }

    private_process_segments(ef);
    private_process_dynamic_section(ef);

    ef->entry = ef->ehdr->e_entry;
    ef->shstrtab = bfrcast(const char *, file + ef->shdrtab[ef->ehdr->e_shstrndx].sh_offset);

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

    for (i = 0; i < ef->ehdr->e_shnum; i++) {
        const struct bfelf_shdr *shdr = &(ef->shdrtab[i]);
        const char *name = &ef->shstrtab[shdr->sh_name];

        if (private_strcmp(name, ".eh_frame") == BFELF_SUCCESS) {
            ef->eh_frame = shdr->sh_addr;
            ef->eh_framesz = shdr->sh_size;
            continue;
        }

        if (private_strcmp(name, ".ctors") == BFELF_SUCCESS) {
            ef->init_array = shdr->sh_addr;
            ef->init_arraysz = shdr->sh_size;
            continue;
        }

        if (private_strcmp(name, ".dtors") == BFELF_SUCCESS) {
            ef->fini_array = shdr->sh_addr;
            ef->fini_arraysz = shdr->sh_size;
            continue;
        }

        if (private_strcmp(name, ".notes") == BFELF_SUCCESS) {
            ef->notes = shdr;
            continue;
        }
    }

    /*
     * The string table is located in both ELF file provided here, as well as
     * in the exec provided to bfelf_loader_add. By the time bfelf_loader_add
     * is called, we assume that the file provided to this function has been
     * deleted, but up to this point, the user is free to use some of the
     * functions (like bfelf_file_get_needed), and for these we need a valid
     * string table, so we store the location of the string table relative
     * to the provided file, and then overwrite this when the user adds the
     * ELF file to the loader, in which case we reference the string table
     * relative to the provided exec.
     */
    ef->strtab = bfcadd(const char *, ef->strtab_offset, bfrcast(bfelf64_addr, file));

    return BFELF_SUCCESS;
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
bfelf_file_get_num_load_instrs(const struct bfelf_file_t *ef)
{
    if (ef == nullptr) {
        return bfinvalid_argument("ef == nullptr");
    }

    return bfscast(int64_t, ef->num_load_instr);
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
bfelf_file_get_load_instr(
    const struct bfelf_file_t *ef, uint64_t index, const struct bfelf_load_instr **instr)
{
    if (ef == nullptr) {
        return bfinvalid_argument("ef == nullptr");
    }

    if (instr == nullptr) {
        return bfinvalid_argument("phdr == nullptr");
    }

    if (index >= ef->num_load_instr) {
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
bfelf_file_get_section_info(
    const struct bfelf_file_t *ef, struct section_info_t *info)
{
    bfelf64_word i = 0;

    if (ef == nullptr) {
        return bfinvalid_argument("ef == nullptr");
    }

    if (info == nullptr) {
        return bfinvalid_argument("info == nullptr");
    }

    if (ef->added == 0) {
        return bfinvalid_argument("ef must be added to a loader first");
    }

    for (i = 0; i < sizeof(struct section_info_t); i++) {
        bfrcast(char *, info)[i] = 0;
    }

    if (ef->init != 0) {
        info->init_addr = ef->init + ef->exec_virt;
    }

    if (ef->fini != 0) {
        info->fini_addr = ef->fini + ef->exec_virt;
    }

    if (ef->init_array != 0) {
        info->init_array_addr = ef->init_array + ef->exec_virt;
        info->init_array_size = ef->init_arraysz;
    }

    if (ef->fini_array != 0) {
        info->fini_array_addr = ef->fini_array + ef->exec_virt;
        info->fini_array_size = ef->fini_arraysz;
    }

    if (ef->eh_frame != 0) {
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
 * @param ef the ELF file to get the entry location from
 * @param addr the resulting address of the entry point
 * @return BFELF_SUCCESS on success, negative on error
 */
static inline int64_t
bfelf_file_get_entry(const struct bfelf_file_t *ef, void **addr)
{
    if (ef == nullptr) {
        return bfinvalid_argument("ef == nullptr");
    }

    if (addr == nullptr) {
        return bfinvalid_argument("addr == nullptr");
    }

    if (ef->added == 0) {
        return bfinvalid_argument("ef must be added to a loader first");
    }

    *addr = bfrcast(void *, ef->entry + ef->exec_virt);
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
 * @param ef the ELF file to get the number of needed files from
 * @return number of needed entries on success, negative on error
 */
static inline int64_t
bfelf_file_get_num_needed(const struct bfelf_file_t *ef)
{
    if (ef == nullptr) {
        return bfinvalid_argument("ef == nullptr");
    }

    return bfscast(int64_t, ef->num_needed);
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
 * @param ef the ELF file to get the needed filename from
 * @param index the shared library name to get
 * @param needed the resulting needed library
 * @return number of needed entries on success, negative on error
 */
static inline int64_t
bfelf_file_get_needed(
    const struct bfelf_file_t *ef, uint64_t index, const char **needed)
{
    if (ef == nullptr) {
        return bfinvalid_argument("ef == nullptr");
    }

    if (needed == nullptr) {
        return bfinvalid_argument("needed == nullptr");
    }

    if (index >= ef->num_needed) {
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
 * @param ef the ELF file to get the total size from
 * @return number of needed entries on success, negative on error
 */
static inline uint64_t
bfelf_file_get_total_size(const struct bfelf_file_t *ef)
{
    if (ef == nullptr) {
        return 0;
    }

    return ef->total_memsz;
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
 * @param ef the ELF file to get the pic/pie info from
 * @return 1 if compiled with PIC/PIE, 0 otherwise
 */
static inline int64_t
bfelf_file_get_pic_pie(const struct bfelf_file_t *ef)
{
    if (ef == nullptr) {
        return bfinvalid_argument("ef == nullptr");
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

    if (loader == nullptr) {
        return bfinvalid_argument("loader == nullptr");
    }

    if (ef == nullptr) {
        return bfinvalid_argument("ef == nullptr");
    }

    if (exec_addr == nullptr) {
        return bfinvalid_argument("exec_addr == nullptr");
    }

    if (loader->num >= MAX_NUM_MODULES) {
        return bfloader_full("increase MAX_NUM_MODULES");
    }

    if (ef->added++ != 0) {
        return bfinvalid_argument("ef already added");
    }

    ef->exec_addr = exec_addr;

    if (ef->start_addr == 0) {
        ef->exec_virt = exec_virt;
    }

    start = bfrcast(bfelf64_addr, ef->exec_addr);

    ef->hash = bfcadd(const bfelf64_word *, ef->hash, start);
    ef->strtab = bfcadd(const char *, ef->strtab_offset, start);
    ef->symtab = bfcadd(const struct bfelf_sym *, ef->symtab, start);
    ef->relatab_dyn = bfcadd(const struct bfelf_rela *, ef->relatab_dyn, start);
    ef->relatab_plt = bfcadd(const struct bfelf_rela *, ef->relatab_plt, start);

    ef->nbucket = ef->hash[0];
    ef->nchain = ef->hash[1];
    ef->bucket = &(ef->hash[2]);
    ef->chain = &(ef->hash[2 + ef->nbucket]);

    /*
     * Sadly, the only way to determine the total size of the dynamic symbol
     * table is to assume that the dynamic string table is always after the
     * dynamic symbol table. :(
     */
    ef->symnum = (bfrcast(bfelf64_addr, ef->strtab) - bfrcast(bfelf64_addr, ef->symtab)) /
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
    bfelf64_word i = 0;

    if (loader == nullptr) {
        return bfinvalid_argument("loader == nullptr");
    }

    if (loader->relocated == 1) {
        return BFELF_SUCCESS;
    }

    for (i = 0; i < loader->num; i++) {
        int64_t ret = private_relocate_symbols(loader, loader->efs[i]);
        if (ret != BFELF_SUCCESS) {
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
bfelf_loader_resolve_symbol(
    const struct bfelf_loader_t *loader, const char *name, void **addr)
{
    int64_t ret = 0;

    struct bfelf_file_t *found_ef = nullptr;
    const struct bfelf_sym *found_sym = nullptr;

    if (loader == nullptr) {
        return bfinvalid_argument("loader == nullptr");
    }

    if (name == nullptr) {
        return bfinvalid_argument("name == nullptr");
    }

    if (addr == nullptr) {
        return bfinvalid_argument("addr == nullptr");
    }

    ret = private_get_sym_global(loader, name, &found_ef, &found_sym);
    if (ret != BFELF_SUCCESS) {
        return ret;
    }

    *addr = found_ef->exec_virt + found_sym->st_value;
    return BFELF_SUCCESS;
}

/* ---------------------------------------------------------------------------------------------- */
/* ELF Loading APIs                                                                               */
/* ---------------------------------------------------------------------------------------------- */

/* @cond */

struct bfelf_binary_t {
    char *exec;
    char *start_addr;
    const char *file;
    uint64_t exec_size;
    uint64_t file_size;
    struct bfelf_file_t ef;
};

static inline int64_t
private_load_binary(struct bfelf_binary_t *binary)
{
    int64_t i = 0;
    int64_t ret = 0;
    int64_t num_segments = 0;
    uint64_t exec_size = 0;

    /*
     * Note:
     *
     * This function expects that binary->file and binary->file_size have
     * already been filled in before executing this function. It will
     * allocate the exec, and then copy each program segment in the provided
     * file into the exec
     */

    if (binary->ef.file == nullptr) {
        ret = bfelf_file_init(binary->file, binary->file_size, &binary->ef);
        if (ret != BF_SUCCESS) {
            return ret;
        }
    }

    exec_size = bfelf_file_get_total_size(&binary->ef);
    num_segments = bfelf_file_get_num_load_instrs(&binary->ef);

    if (binary->exec_size == 0) {
        binary->exec_size = exec_size;
    }
    else {
        if (binary->exec_size < exec_size) {
            return bfinvalid_argument("binary->exec_size < exec_size");
        }
    }

    /*
     * TODO:
     *
     * Currently we allocate RWE memory instead of W^E. This code is used in
     * two different places, the hypervisor and guest applications. In both
     * cases this memory is changed to W^E by either the hypervisor's memory
     * manager, or by a set of hypercalls. The only time the memory is actually
     * used as RWE is during the initialization of the hypervisor, and not it's
     * normal operation.
     *
     * Since this has to be cross platform, most operating systems support some
     * form of RWE so this is what we use today. The risk for attack is limited
     * to the initialization of the hypervisor which in most cases will be
     * performed by a root-of-trust, so the attack surface is low. Still,
     * someday it would be nice to find an mprotect like function for all
     * operating systems such that memory can be allocated RW, and changed
     * to RE as needed. If this functionality is found, the code here will have
     * to be changed to support this.
     *
     * Note:
     *
     * Also note that we first make sure that this memory has not already
     * been allocated for us. This is only the case for guest VMs that act more
     * like traditional virtual machines where RAM is allocated. In this case,
     * a giant chunk of RAM is allocated, and the ELF file takes up the first
     * portion of this RAM. The rest is left for the VM to allocate as needed.
     * In this case, we just make sure the allocated memory is large enough,
     * and then we load ourselves in the already allocated memory.
     *
     * Finally, it is possible for the above code to only dictate the size of
     * RAM, but leave the allocation of this RAM to use in the code below so
     * that permissions can be changed as needed when this is supported.
     */

    if (binary->exec == nullptr) {
        binary->exec = bfscast(char *, platform_alloc_rwe(binary->exec_size));
    }

    if (binary->exec == nullptr) {
        return bfout_of_memory("unable to allocate exec RWE memory");
    }

    platform_memset(binary->exec, 0, binary->exec_size);

    for (i = 0; i < num_segments; i++) {
        const struct bfelf_load_instr *instr = nullptr;

        const char *src = nullptr;
        char *dst = nullptr;

        ret = bfelf_file_get_load_instr(&binary->ef, bfscast(uint64_t, i), &instr);
        bfignored(ret);

        if (instr != nullptr) {
            uint64_t dst_size = binary->exec_size - instr->mem_offset;
            uint64_t src_size = binary->file_size - instr->file_offset;

            dst = bfadd(char *, binary->exec, instr->mem_offset);
            src = bfcadd(const char *, binary->file, instr->file_offset);

            ret = platform_memcpy(dst, dst_size, src, src_size, instr->filesz);
            if (ret != SUCCESS) {
                return bfinvalid_argument("memcpy failed with unknown reason");
            }
        }
    }

    return BF_SUCCESS;
}

static inline int64_t
private_relocate_binaries(
    struct bfelf_binary_t *binaries, uint64_t num_binaries, struct bfelf_loader_t *loader)
{
    uint64_t i = 0;
    int64_t ret = 0;

    for (i = 0; i < num_binaries; i++) {

        if (binaries[i].start_addr == 0) {
            ret = bfelf_loader_add(loader, &binaries[i].ef, binaries[i].exec, binaries[i].exec);
            bfignored(ret);
        }
        else {
            ret = bfelf_loader_add(loader, &binaries[i].ef, binaries[i].exec, binaries[i].start_addr);
            bfignored(ret);
        }

        if (binaries[i].ef.start_addr != 0) {
            binaries[i].start_addr = (char *)binaries[i].ef.start_addr;
        }
    }

    ret = bfelf_loader_relocate(loader);
    if (ret != BFELF_SUCCESS) {
        return ret;
    }

    return BF_SUCCESS;
}

static inline int64_t
private_crt_info(
    struct bfelf_binary_t *binaries, uint64_t num_binaries, struct crt_info_t *crt_info)
{
    uint64_t i = 0;

    for (i = 0; i < num_binaries; i++) {

        int64_t ret = 0;
        struct section_info_t section_info;

        ret = bfelf_file_get_section_info(&binaries[i].ef, &section_info);
        bfignored(ret);

        crt_info->info[crt_info->info_num++] = section_info;
    }

    return BF_SUCCESS;
}

/* @endcond */

/**
 * Load
 *
 * Takes an array of ELF binaries and loads them. The resulting output is an
 * entry point that can be executed. The CRT info and the ELF loader are also
 * provided as a result.
 *
 * @note This function gets the entry point of the last binary provided.
 *     For this reason, the main executable should ALWAYS be last in the list
 *     of ELF binaries provided
 *
 * @note It is assumed that file and file_size are already provided for each
 *     ELF binary. This function will loop through each binary, and use this
 *     information to actually load everything into ELF file specific
 *     structures.
 *
 * @expects binaries != null
 * @expects num_binaries != 0 && num_binaries < MAX_NUM_MODULES
 * @expects entry != null
 * @expects crt_info != null
 * @expects loader != null
 * @ensures none
 *
 * @param binaries the list of ELF binaries to load
 * @param num_binaries the number of binaries provided
 * @param entry the resulting entry point
 * @param crt_info the resulting CRT info
 * @param loader the resulting ELF loader
 * @return BFELF_SUCCESS on success, negative on error
 */
static inline int64_t
bfelf_load(
    struct bfelf_binary_t *binaries, uint64_t num_binaries, void **entry,
    struct crt_info_t *crt_info, struct bfelf_loader_t *loader)
{
    uint64_t i = 0;
    int64_t ret = 0;

    if (binaries == nullptr) {
        return bfinvalid_argument("binaries == nullptr");
    }

    if (num_binaries == 0 || num_binaries >= MAX_NUM_MODULES) {
        return bfinvalid_argument("num_binaries == 0 || num_binaries >= MAX_NUM_MODULES");
    }

    if (loader == nullptr) {
        return bfinvalid_argument("loader == nullptr");
    }

    for (i = 0; i < num_binaries; i++) {
        ret = private_load_binary(&binaries[i]);
        if (ret != BF_SUCCESS) {
            return ret;
        }
    }

    ret = private_relocate_binaries(binaries, num_binaries, loader);
    if (ret != BF_SUCCESS) {
        return ret;
    }

    if (crt_info != nullptr) {
        ret = private_crt_info(binaries, num_binaries, crt_info);
        bfignored(ret);
    }

    if (entry != nullptr) {
        ret = bfelf_file_get_entry(&binaries[num_binaries - 1].ef, entry);
        bfignored(ret);
    }

    return BF_SUCCESS;
}

/**
 * Set Args
 *
 * Tells the CRT info to use the standard main(arc, argv) function, and sets
 * the values of these. This information will be passed to the resulting
 * entry point
 *
 * @expects crt_info != nullptr
 * @ensures returns BFELF_SUCCESS if params == valid
 *
 * @param crt_info the CRT info to fill where the args will be stored
 * @param argc the total number of args
 * @param argv the args
 * @return BFELF_SUCCESS on success, negative on error
 */
static inline int64_t
bfelf_set_args(struct crt_info_t *crt_info, int argc, const char **argv)
{
    if (crt_info == nullptr) {
        return bfinvalid_argument("crt_info == nullptr");
    }

    crt_info->argc = argc;
    crt_info->argv = argv;
    crt_info->arg_type = 0;

    return BF_SUCCESS;
}

/**
 * Set Integer Args
 *
 * There are two different types of main functions supported: the standard
 * main(arc, argv) and then another form that uses 64bit integers in the
 * form int64_t bfmain(int64_t, int64_t, int64_t, int64_t). This function tells
 * the CRT info to use the integer version, and sets the values of these.
 * This information will be passed to the resulting entry point
 *
 * @expects crt_info != nullptr
 * @ensures returns BFELF_SUCCESS if params == valid
 *
 * @param crt_info the CRT info to fill where the args will be stored
 * @param request the request id
 * @param arg1 integer arg #1
 * @param arg2 integer arg #2
 * @param arg3 integer arg #3
 * @return BFELF_SUCCESS on success, negative on error
 */
static inline int64_t
bfelf_set_integer_args(
    struct crt_info_t *crt_info, uintptr_t request, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{
    if (crt_info == nullptr) {
        return bfinvalid_argument("crt_info == nullptr");
    }

    crt_info->request = request;
    crt_info->arg1 = arg1;
    crt_info->arg2 = arg2;
    crt_info->arg3 = arg3;
    crt_info->arg_type = 1;

    return BF_SUCCESS;
}

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

#include <bfgsl.h>
#include <bffile.h>
#include <bfstring.h>

#include <string>
#include <vector>
#include <memory>
#include <exception>

/* @cond */

inline auto
private_read_binary(
    gsl::not_null<file *> f, const std::string &filename, bfelf_binary_t &binary)
{
    auto buffer = f->read_binary(filename);

    binary.file = buffer.get();
    binary.file_size = buffer.size();

    return buffer;
}

inline auto
private_get_needed_list(const bfelf_file_t &ef)
{
    int64_t ret = 0;
    std::vector<std::string> list;

    for (auto i = 0LL; i < bfelf_file_get_num_needed(&ef); i++) {
        const char *needed = nullptr;

        ret = bfelf_file_get_needed(&ef, static_cast<uint64_t>(i), &needed);
        bfignored(ret);

        list.emplace_back(needed);
    }

    return list;
}

/* @endcond */

/**
 * Read Binary and Get Needed List
 *
 * This function takes a filename, and a list of paths to locate the
 * provide file. If the ELF binary is located, the function then parses
 * the ELF file and returns the list of binaries that are needed (i.e.
 * have to be linked to this ELF binary to resolve needed symbols). If
 * the binary cannot be located, an exception is thrown.
 *
 * @expects none
 * @ensures none
 *
 * @param f the file object to read the located filename
 * @param filename the name of the ELF binary to get the needed list from
 * @param paths a list of paths to locate the ELF binary from
 * @param buffer the buffer to read the ELF binary into
 * @param binary the binary object
 * @return list of needed binaries or throws
 */
inline auto
bfelf_read_binary_and_get_needed_list(
    gsl::not_null<file *> f, const std::string &filename,
    const std::vector<std::string> &paths, bfn::buffer &buffer, bfelf_binary_t &binary)
{
    buffer = private_read_binary(f, filename, binary);

    auto ret = bfelf_file_init(buffer.data(), buffer.size(), &binary.ef);
    if (ret != BFELF_SUCCESS) {
        throw std::runtime_error("bfelf_file_init failed: " + std::to_string(ret));
    }

    auto list = f->find_files(private_get_needed_list(binary.ef), paths);
    return list;
}

/**
 * Binaries Info
 *
 * Provides a C++ wrapper for all of the ELF structures that are needed to
 * load an ELF binary.
 */
class binaries_info
{
public:

    using index_type = std::size_t;             ///< Index type
    using info_type = crt_info_t;               ///< CRT info type
    using entry_type = void *;                  ///< Entry point address type
    using loader_type = bfelf_loader_t;         ///< ELF loader type

    /**
     * Constructor
     *
     * Loads the file provided, and searches the needed list to identify
     * any other files that are needed for symbol resolution.
     *
     * @expects none
     * @ensures none
     *
     * @param f the file object to read the located filename
     * @param filename the name of the ELF binary to load
     * @param paths a list of paths to locate the ELF binary from
     * @param load if true, loads the binaries
     */
    binaries_info(
        gsl::not_null<file *> f, const std::string &filename, const std::vector<std::string> &paths, bool load = true)
    {
        bfn::buffer data;
        bfelf_binary_t binary = {};

        auto filenames = bfelf_read_binary_and_get_needed_list(f, filename, paths, data, binary);

        this->init_binaries(f, filenames);
        this->push_binary(std::move(data), std::move(binary));

        auto ___ = gsl::on_failure([&] {
            this->unload_binaries();
        });

        if (load) {
            this->load_binaries();
        }
    }

    /**
     * Constructor
     *
     * Loads all of the files provided. This does not search the needed list
     * and instead expects that the list of binaries provided is complete.
     *
     * @expects none
     * @ensures none
     *
     * @param f the file object to read the located filename
     * @param filenames the list of files to load
     * @param load if true, loads the binaries
     */
    binaries_info(
        gsl::not_null<file *> f, const std::vector<std::string> &filenames, bool load = true)
    {
        this->init_binaries(f, filenames);

        auto ___ = gsl::on_failure([&] {
            this->unload_binaries();
        });

        if (load) {
            this->load_binaries();
        }
    }

    /**
     * Default Destructor
     */
    ~binaries_info()
    { this->unload_binaries(); }

    /**
     * Set Args
     *
     * Sets the argc and argv for this binary.
     *
     * @expects none
     * @ensures none
     *
     * @param argc the number of arguments to pass to this binary
     * @param argv the arguments to pass to this binary
     */
    void
    set_args(int argc, const char **argv)
    {
        auto ret = bfelf_set_args(&m_info, argc, argv);
        bfignored(ret);
    }

    /**
     * Get Main ELF Binary
     *
     * Returns the main ELF binary (i.e. does not return the shared libraries
     * needed by the main binary)
     *
     * @expects none
     * @ensures none
     *
     * @return main binary
     */
    auto &
    ef()
    { return m_binaries.back().ef; }

    /**
     * Get Specific ELF Binary
     *
     * Returns a specific ELF binary given an index
     *
     * @expects index is valid
     * @ensures none
     *
     * @param index of the ELF binary to get
     * @return main binary
     */
    auto &
    ef(index_type index)
    { return m_binaries.at(index).ef; }

    /**
     * Get A Specific Binary
     *
     * @expects none
     * @ensures none
     *
     * @param index of the specific binary to get
     * @return returns a specific binary
     */
    auto &
    at(index_type index)
    { return m_binaries.at(index); }

    /**
     * Get The First Binary
     *
     * @expects none
     * @ensures none
     *
     * @return returns the first binary
     */
    auto &
    front()
    { return m_binaries.front(); }

    /**
     * Get The Last Binary
     *
     * @expects none
     * @ensures none
     *
     * @return returns the last binary
     */
    auto &
    back()
    { return m_binaries.back(); }

    /**
     * Get Binaries
     *
     * @expects none
     * @ensures none
     *
     * @return returns the Binaries
     */
    auto &
    binaries()
    { return m_binaries; }

    /**
     * Get CRT Info
     *
     * @expects none
     * @ensures none
     *
     * @return returns CRT info
     */
    const auto &
    info() const
    { return m_info; }

    /**
     * Get Entry Point Address
     *
     * @expects none
     * @ensures none
     *
     * @return returns entry point address
     */
    auto
    entry() const
    { return m_entry; }

    /**
     * Get ELF Loader
     *
     * @expects none
     * @ensures none
     *
     * @return returns the ELF loader
     */
    auto &
    loader()
    { return m_loader; }

private:

    void
    push_binary(bfn::buffer &&data, bfelf_binary_t &&binary)
    {
        m_datas.push_back(std::move(data));
        m_binaries.push_back(std::move(binary));
    }

    void
    init_binaries(gsl::not_null<file *> f, const std::vector<std::string> &filenames)
    {
        expects(!filenames.empty());

        for (const auto &filename : filenames) {
            bfelf_binary_t binary = {};
            this->push_binary(private_read_binary(f, filename, binary), std::move(binary));
        }
    }

    void
    load_binaries()
    {
        auto ret = bfelf_load(m_binaries.data(), m_binaries.size(), &m_entry, &m_info, &m_loader);
        if (ret != BF_SUCCESS) {
            throw std::runtime_error("bfelf_load failed: " + bfn::to_string(ret, 16));
        }
    }

    void
    unload_binaries()
    {
        for (const auto &binary : m_binaries) {
            platform_free_rwe(binary.exec, binary.exec_size);
        }
    }

    info_type m_info{};
    entry_type m_entry{};
    loader_type m_loader{};

    std::vector<bfelf_binary_t> m_binaries;
    std::vector<file::binary_data> m_datas;

public:

    /** @cond */

    binaries_info(binaries_info &&) noexcept = default;
    binaries_info &operator=(binaries_info &&) noexcept = default;

    binaries_info(const binaries_info &) = delete;
    binaries_info &operator=(const binaries_info &) = delete;

    /** @endcond */
};

#endif

#pragma pack(pop)
#endif
