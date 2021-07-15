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

#ifndef BFELF_ELF64_SHDR_T_H
#define BFELF_ELF64_SHDR_T_H

#include <types.h>

#pragma pack(push, 1)

/**
 * @struct bfelf_elf64_shdr_t
 *
 * <!-- description -->
 *   @brief Sections provide different information from relocation
 *     instructions to strings stored in the executable.
 *
 * <!-- notes -->
 *   @note IMPORTANT: If sections are ever actually needed, the offset
 *     cannot actually be a byte array, but instead needs to be a union
 *     of the different types that the section might actually be. This
 *     is AUTOSAR compliant because the type field is the "tag", making
 *     the union a tagged union which is allowed. This will ensure that
 *     you can parse the different sections without having to do casts.
 */
struct bfelf_elf64_shdr_t
{
    uint32_t sh_name;      /**< Name of section */
    uint32_t sh_type;      /**< Type of section */
    uint32_t sh_flags;     /**< Section attributes */
    uint64_t sh_addr;      /**< Virtual address of section */
    uint8_t *sh_offset;    /**< Offset of section in ELF file */
    uint32_t sh_size;      /**< Size of section */
    uint32_t sh_link;      /**< Section linked to this section */
    uint32_t sh_info;      /**< Section information */
    uint32_t sh_addralign; /**< Section alignment */
    uint32_t sh_entsize;   /**< Size of section entries */
};

#pragma pack(pop)

#endif
