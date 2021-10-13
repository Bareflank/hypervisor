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

#ifndef ALLOC_AND_COPY_MK_CODE_ALIASES_H
#define ALLOC_AND_COPY_MK_CODE_ALIASES_H

#include <code_aliases_t.h>
#include <types.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * <!-- description -->
     *   @brief The function's main purpose is allocate pages for all of the
     *     executable code that is currently linked into the kernel module, and
     *     copy this code into the newly allocated pages so that they can be
     *     mapped into the microkernel's page tables, creating an alias.
     *     The following diagram is what we are doing here:
     *
     *                          |-------> physical address (OS kernel)
     *                          |
     *     virtual address <----|
     *                          |
     *                          |-------> physical address (microkernel)
     *
     *     As you can see, the same virtual address for both the OS kernel and
     *     the microkernel point to two different physical addresses. The
     *     physical address for the microkernel is the alias, and we create
     *     the alias by copying the page located in the OS kenrel to the page
     *     located in the microkernel. This is done because we cannot actually
     *     get the physical address of the OS kernel, but we can access the
     *     contents of the page using the virtual address. So we copy the page
     *     to a page that we can get the physical address of and point the
     *     microkernel to that page instead. It should be noted that on Linux,
     *     if you do try to get the physical address of the code that we need
     *     to map into the microkernel, you will actually get what looks like
     *     a valid physical address, but be warned that the page it returns
     *     is actually garbage. You can only get the physical address of
     *     memory that is allocated using vmalloc(), which is why we need to
     *     create the aliases, as we need the physical address of the code so
     *     that we can map it into the microkernel's page tables.
     *
     * <!-- inputs/outputs -->
     *   @param pmut_a a pointer to a code_aliases_t that will store the
     *     resulting aliases.
     *   @return LOADER_SUCCESS on success, LOADER_FAILURE on failure.
     */
    NODISCARD int64_t alloc_and_copy_mk_code_aliases(struct code_aliases_t *const pmut_a) NOEXCEPT;

#ifdef __cplusplus
}
#endif

#endif
