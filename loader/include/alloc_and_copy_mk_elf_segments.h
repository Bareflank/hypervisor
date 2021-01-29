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

#ifndef ALLOC_AND_COPY_MK_ELF_SEGMENTS_H
#define ALLOC_AND_COPY_MK_ELF_SEGMENTS_H

#include <elf_segment_t.h>
#include <span_t.h>

/**
 * <!-- description -->
 *   @brief When the start VMM function is executed, the user must provide
 *     the address and size of the microkernel ELF file to be loaded and
 *     executed. Once this memory is mapped into the kernel address space,
 *     we need to allocate memory for each program segment in the ELF file
 *     and copy the contents of each ELF segment into the newly allocated
 *     memory. This is because we cannot execute directly from the ELF file
 *     itself, but instead of execute from the "loaded" version of the ELF
 *     file. Later, we will take each ELF segment and map it into the
 *     microkernel's memory space, ensuring the microkernel is capable of
 *     being executed given it's memory space.
 *
 * <!-- inputs/outputs -->
 *   @param mk_elf_file the ELF file to copy the segments from
 *   @param mk_elf_segments where to copy the ELF segments too
 *   @return 0 on success, LOADER_FAILURE on failure.
 */
int64_t alloc_and_copy_mk_elf_segments(
    struct span_t const *const mk_elf_file,
    struct elf_segment_t *const mk_elf_segments);

#endif
