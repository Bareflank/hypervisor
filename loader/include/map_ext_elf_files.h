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

#ifndef MAP_EXT_ELF_FILES_H
#define MAP_EXT_ELF_FILES_H

#include <elf_file_t.h>
#include <root_page_table_t.h>
#include <types.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * <!-- description -->
     *   @brief This function maps the extensions's ELF files into the
     *     microkernel's root page tables.
     *
     * <!-- inputs/outputs -->
     *   @param ext_elf_files a pointer to the ext_elf_files to map
     *   @param pmut_rpt the root page table to map the ELF files into
     *   @return LOADER_SUCCESS on success, LOADER_FAILURE on failure.
     */
    NODISCARD int64_t map_ext_elf_files(
        struct elf_file_t const *const ext_elf_files, root_page_table_t *const pmut_rpt) NOEXCEPT;

#ifdef __cplusplus
}
#endif

#endif
