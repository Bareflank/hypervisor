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

#include <constants.h>
#include <debug.h>
#include <map_4k_page_rw.h>
#include <platform.h>
#include <pml4t_t.h>
#include <span_t.h>

/**
 * <!-- description -->
 *   @brief This function maps an extensions's ELF file into the
 *     microkernel's root page tables.
 *
 * <!-- inputs/outputs -->
 *   @param file a pointer to a span_t that stores the ELF file
 *     being mapped
 *   @param pml4t the root page table to map the stack into
 *   @return 0 on success, LOADER_FAILURE on failure.
 */
static int64_t
map_ext_elf_file(struct span_t const *const file, struct pml4t_t *const pml4t)
{
    uint64_t off;

    for (off = ((uint64_t)0); off < file->size; off += HYPERVISOR_PAGE_SIZE) {
        if (map_4k_page_rw(file->addr + off, ((uint64_t)0), pml4t)) {
            BFERROR("map_4k_page_rw failed\n");
            return LOADER_FAILURE;
        }
    }

    return LOADER_SUCCESS;
}

/**
 * <!-- description -->
 *   @brief This function maps the extensions's ELF files into the
 *     microkernel's root page tables.
 *
 * <!-- inputs/outputs -->
 *   @param files a pointer to a span_t array that stores the ELF files
 *     being mapped
 *   @param pml4t the root page table to map the ELF files into
 *   @return 0 on success, LOADER_FAILURE on failure.
 */
int64_t
map_ext_elf_files(struct span_t const *const files, struct pml4t_t *const pml4t)
{
    uint64_t idx;

    for (idx = ((uint64_t)0); idx < HYPERVISOR_MAX_EXTENSIONS; ++idx) {
        if (map_ext_elf_file(&files[idx], pml4t)) {
            BFERROR("map_ext_elf_file failed\n");
            return LOADER_FAILURE;
        }
    }

    return LOADER_SUCCESS;
}
