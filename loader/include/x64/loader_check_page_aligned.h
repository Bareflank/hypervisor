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

#ifndef LOADER_CHECK_PAGE_ALIGNED_H
#define LOADER_CHECK_PAGE_ALIGNED_H

#include <loader_arch_context.h>
#include <loader_debug.h>
#include <loader_types.h>

/**
 * <!-- description -->
 *   @brief Checks to see if a provided address, given a provided
 *     context, is a page aligned.
 *
 * <!-- inputs/outputs -->
 *   @param virt the address to check
 *   @param arch_context the architecture specific context for this cpu
 *   @return returns 0 if the address is page aligned, FAILURE otherwise
 */
static inline int
check_page_aligned(uintptr_t addr, struct loader_arch_context_t *context)
{
    if (NULL == context) {
        BFERROR("invalid argument\n");
        return FAILURE;
    }

    if (0U == context->page_size) {
        BFERROR("invalid page size\n");
        return FAILURE;
    }

    if ((addr & (context->page_size - 1)) != 0) {
        BFERROR("address not page aligned: 0x%" PRIxPTR "\n", addr);
        return FAILURE;
    }

    return 0;
}

#endif
