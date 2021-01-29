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

#ifndef MAP_MK_ELF_SEGMENTS_H
#define MAP_MK_ELF_SEGMENTS_H

#include <elf_segment_t.h>
#include <pml4t_t.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief This function maps the microkernel's ELF segments into the
 *     microkernel's root page tables.
 *
 * <!-- inputs/outputs -->
 *   @param segments a pointer to a elf_segment_t array that stores the ELF
 *     segments being mapped
 *   @param pml4t the root page table to map the ELF segments into
 *   @return 0 on success, LOADER_FAILURE on failure.
 */
int64_t map_mk_elf_segments(
    struct elf_segment_t const *const segments, struct pml4t_t *const pml4t);

#endif
