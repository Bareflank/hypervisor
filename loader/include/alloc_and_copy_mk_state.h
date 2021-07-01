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

#ifndef ALLOC_AND_COPY_MK_STATE_H
#define ALLOC_AND_COPY_MK_STATE_H

#include <elf_file_t.h>
#include <root_page_table_t.h>
#include <span_t.h>
#include <state_save_t.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief The function's main purpose is to set up the state for the
 *     microkernel.
 *
 * <!-- inputs/outputs -->
 *   @param rpt the mkcrokernel's root page table
 *   @param mk_elf_file the microkernel's ELF file
 *   @param mk_stack the microkernel's stack
 *   @param mk_stack_virt the microkernel's virtual address of the stack
 *   @param state where to save the newly set up state to
 *   @return LOADER_SUCCESS on success, LOADER_FAILURE on failure.
 */
int64_t alloc_and_copy_mk_state(
    root_page_table_t const *const rpt,
    struct elf_file_t const *const mk_elf_file,
    struct span_t const *const mk_stack,
    uint64_t const mk_stack_virt,
    struct state_save_t **const state);

#endif
