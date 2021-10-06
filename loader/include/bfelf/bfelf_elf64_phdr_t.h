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

#include <types.h>

#pragma pack(push, 1)

/** @brief defines p_type for unused entry */
#define bfelf_pt_null ((uint32_t)0U)
/** @brief defines p_type for a loadable segment */
#define bfelf_pt_load ((uint32_t)1U)
/** @brief defines p_type for dynamic linking tables */
#define bfelf_pt_dynamic ((uint32_t)2U)
/** @brief defines p_type for the program interpreter path */
#define bfelf_pt_interp ((uint32_t)3U)
/** @brief defines p_type for note sections */
#define bfelf_pt_note ((uint32_t)4U)
/** @brief defines p_type for reserved */
#define bfelf_pt_shlib ((uint32_t)5U)
/** @brief defines p_type for the program header table */
#define bfelf_pt_phdr ((uint32_t)6U)
/** @brief defines p_type for the tls segment */
#define bfelf_pt_tls ((uint32_t)7U)
/** @brief defines p_type for environment-specific use (lo) */
#define bfelf_pt_loos ((uint32_t)0x60000000U)
/** @brief defines p_type for the GNU stack segment */
#define bfelf_pt_gnu_stack ((uint32_t)0x6474e551U)
/** @brief defines p_type for environment-specific use (hi) */
#define bfelf_pt_hios ((uint32_t)0x6FFFFFFFU)
/** @brief defines p_type for processor-specific use (lo) */
#define bfelf_pt_loproc ((uint32_t)0x70000000U)
/** @brief defines p_type for processor-specific use (hi) */
#define bfelf_pt_hiproc ((uint32_t)0x7FFFFFFFU)

/** @brief defines p_flags for execute permissions */
#define bfelf_pf_x ((uint32_t)1U)
/** @brief defines p_flags for write permissions */
#define bfelf_pf_w ((uint32_t)2U)
/** @brief defines p_flags for read permissions */
#define bfelf_pf_r ((uint32_t)4U)
/** @brief defines p_flags for environment-specific use */
#define bfelf_pf_maskos ((uint32_t)0x00FF0000U)
/** @brief defines p_flags for environment-specific use */
#define bfelf_pf_maskproc ((uint32_t)0xFF000000U)

/**
 * <!-- description -->
 *   @brief In executable and shared object files, sections are grouped
 *     into segments for loading. The program header table contains a
 *     list of entries describing each segment.
 */
struct bfelf_elf64_phdr_t
{
    uint32_t p_type;   /**< Type of segment */
    uint32_t p_flags;  /**< Segment attributes */
    uint8_t *p_offset; /**< Offset of segment in ELF file */
    uint64_t p_vaddr;  /**< Virtual address of segment */
    uint64_t p_paddr;  /**< Physical address of segment */
    uint64_t p_filesz; /**< Size of segment in ELF file */
    uint64_t p_memsz;  /**< Size of segment in memory */
    uint64_t p_align;  /**< Segment alignment */
};

#pragma pack(pop)

#endif
