/**
 * @copyright
 * Copyright (C) 2020 Assured Information Security, Inc.
 *
 * @copyright
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * @copyright
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * @copyright
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef BFELF_ELF64_PHDR_T_H
#define BFELF_ELF64_PHDR_T_H

#include "bfelf_elf64_ehdr_t.h"
#include "bfelf_types.h"

#pragma pack(push, 1)

/** @brief defines p_type for unused entry */
#define bfelf_pt_null ((bfelf_elf64_word)0U)
/** @brief defines p_type for a loadable segment */
#define bfelf_pt_load ((bfelf_elf64_word)1U)
/** @brief defines p_type for dynamic linking tables */
#define bfelf_pt_dynamic ((bfelf_elf64_word)2U)
/** @brief defines p_type for the program interpreter path */
#define bfelf_pt_interp ((bfelf_elf64_word)3U)
/** @brief defines p_type for note sections */
#define bfelf_pt_note ((bfelf_elf64_word)4U)
/** @brief defines p_type for reserved */
#define bfelf_pt_shlib ((bfelf_elf64_word)5U)
/** @brief defines p_type for the program header table */
#define bfelf_pt_phdr ((bfelf_elf64_word)6U)
/** @brief defines p_type for the tls segment */
#define bfelf_pt_tls ((bfelf_elf64_word)7U)
/** @brief defines p_type for environment-specific use (lo) */
#define bfelf_pt_loos ((bfelf_elf64_word)0x60000000U)
/** @brief defines p_type for the GNU stack segment */
#define bfelf_pt_gnu_stack ((bfelf_elf64_word)0x6474e551U)
/** @brief defines p_type for environment-specific use (hi) */
#define bfelf_pt_hios ((bfelf_elf64_word)0x6FFFFFFFU)
/** @brief defines p_type for processor-specific use (lo) */
#define bfelf_pt_loproc ((bfelf_elf64_word)0x70000000U)
/** @brief defines p_type for processor-specific use (hi) */
#define bfelf_pt_hiproc ((bfelf_elf64_word)0x7FFFFFFFU)

/** @brief defines p_flags for execute permissions */
#define bfelf_pf_x ((bfelf_elf64_word)1U)
/** @brief defines p_flags for write permissions */
#define bfelf_pf_w ((bfelf_elf64_word)2U)
/** @brief defines p_flags for read permissions */
#define bfelf_pf_r ((bfelf_elf64_word)4U)
/** @brief defines p_flags for environment-specific use */
#define bfelf_pf_maskos ((bfelf_elf64_word)0x00FF0000U)
/** @brief defines p_flags for environment-specific use */
#define bfelf_pf_maskproc ((bfelf_elf64_word)0xFF000000U)

/**
 * @struct bfelf_elf64_phdr_t
 *
 * <!-- description -->
 *   @brief In executable and shared object files, sections are grouped
 *     into segments for loading. The program header table contains a
 *     list of entries describing each segment.
 */
struct bfelf_elf64_phdr_t
{
    bfelf_elf64_word p_type;    /**< Type of segment */
    bfelf_elf64_word p_flags;   /**< Segment attributes */
    bfelf_elf64_off p_offset;   /**< Offset in file */
    bfelf_elf64_addr p_vaddr;   /**< Virtual address in memory */
    bfelf_elf64_addr p_paddr;   /**< Reserved */
    bfelf_elf64_xword p_filesz; /**< Size of segment in file */
    bfelf_elf64_xword p_memsz;  /**< Size of segment in memory */
    bfelf_elf64_xword p_align;  /**< Alignment of segment */
};

/** @brief converts a uint8_t * to a struct bfelf_elf64_phdr_t * */
#define to_phdr(a) ((struct bfelf_elf64_phdr_t *)a)

/**
 * <!-- description -->
 *   @brief Returns a pointer to the program header table given a
 *     pointer to an ELF file.
 *
 * <!-- inputs/outputs -->
 *   @param file a pointer to the ELF file to get the program header
 *     table from.
 *   @param phdrtab where to output the program header table.
 *   @return returns 0 on success or an error code otherwise.
 */
static inline int64_t
get_elf64_phdrtab(uint8_t const *const file, struct bfelf_elf64_phdr_t const **const phdrtab)
{
    if (((void *)0) == file) {
        return BFELF_INVALID_ARGUMENT;
    }

    if (((void *)0) == phdrtab) {
        return BFELF_INVALID_ARGUMENT;
    }

    *phdrtab = to_phdr(&file[to_ehdr(file)->e_phoff]);
    return 0;
}

#pragma pack(pop)

#endif
