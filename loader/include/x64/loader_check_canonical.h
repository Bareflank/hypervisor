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

#ifndef LOADER_CHECK_CANONICAL_H
#define LOADER_CHECK_CANONICAL_H

#include <loader_arch_context.h>
#include <loader_debug.h>
#include <loader_types.h>
#include <loader.h>

/**
 * <!-- description -->
 *   @brief Checks to see if a provided virtual address, given a provided
 *     context, is a canonical address.
 *
 * <!-- inputs/outputs -->
 *   @param virt the virtual address to check
 *   @param arch_context the architecture specific context for this cpu
 *   @return returns 0 if the address is canonical, LOADER_FAILURE otherwise
 */
static inline int
check_canonical(uintptr_t virt, struct loader_arch_context_t *arch_context)
{
    uintptr_t upper = ~((uintptr_t)0U);
    uintptr_t lower = 1U;

    if (NULL == arch_context) {
        BFERROR("invalid argument\n");
        return LOADER_FAILURE;
    }

    if (0U == arch_context->physical_address_bits) {
        BFERROR("invalid physical address bits\n");
        return LOADER_FAILURE;
    }

    upper = (upper << (arch_context->physical_address_bits - 1U));
    lower = (lower << (arch_context->physical_address_bits - 1U)) - 1U;

    if (((virt < upper) && (virt > lower))) {
        BFERROR("virt address not canonical: 0x%" PRIxPTR "\n", virt);
        return LOADER_FAILURE;
    }

    return 0;
}

#endif
