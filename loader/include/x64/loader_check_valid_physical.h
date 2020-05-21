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

#ifndef LOADER_CHECK_VALID_PHYSICAL_H
#define LOADER_CHECK_VALID_PHYSICAL_H

#include <loader_arch_context.h>
#include <loader_debug.h>
#include <loader_types.h>

/**
 * <!-- description -->
 *   @brief Checks to see if a provided physical address, given a provided
 *     context, is a valid physical address.
 *
 * <!-- inputs/outputs -->
 *   @param virt the physical address to check
 *   @param arch_context the architecture specific context for this cpu
 *   @return returns 0 if the address is valid, FAILURE otherwise
 */
static inline int
check_valid_physical(uintptr_t phys, struct loader_arch_context_t *context)
{
    uintptr_t max = 1U;

    if (NULL == context) {
        BFERROR("invalid argument\n");
        return FAILURE;
    }

    if (0U == context->physical_address_bits) {
        BFERROR("invalid physical address bits\n");
        return FAILURE;
    }

    max <<= context->physical_address_bits;
    if (phys >= max) {
        BFERROR("phys address not valid: 0x%" PRIxPTR "\n", phys);
        return FAILURE;
    }

    return 0;
}

#endif
