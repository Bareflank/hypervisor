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

#include <global_descriptor_table_register_t.h>
#include <platform.h>
#include <types.h>

/** @brief defines the first set of bits associated with the limit field */
#define LIMIT_MASK1 ((uint64_t)0x000000000000FFFF)
/** @brief defines the second set of bits associated with the limit field */
#define LIMIT_MASK2 ((uint64_t)0x000F000000000000)
/** @brief defines the second set of bits associated with the limit field */
#define LIMIT_MASKG ((uint64_t)0x0000000000000FFF)
/** @brief defines the bit location of the first set of limit field */
#define LIMIT_SHIFT1 ((uint64_t)0)
/** @brief defines the bit location of the second set of limit field */
#define LIMIT_SHIFT2 ((uint64_t)32)
/** @brief defines the bit location of the third set of limit field */
#define LIMIT_SHIFTG ((uint64_t)12)

/** @brief defines the bit location of the G bit in the attrib field */
#define GRANULARITY_BIT ((uint64_t)0x0080000000000000)

/**
 * <!-- description -->
 *   @brief Sets a GDT descriptor's limit given a GDT and a selector into
 *     the provided GDT.
 *
 * <!-- inputs/outputs -->
 *   @param gdtr a pointer to the gdtr that stores the GDT to get from
 *   @param selector the selector of the descriptor in the provided GDT
 *     to get from
 *   @param pmut_limit a pointer to store the the resulting limit to
 */
void
get_gdt_descriptor_limit(
    struct global_descriptor_table_register_t const *const gdtr,
    uint16_t const selector,
    uint32_t *const pmut_limit) NOEXCEPT
{
    uint64_t const idx64 = ((uint64_t)selector) >> ((uint64_t)3);

    platform_expects(NULLPTR != gdtr);
    platform_expects(NULLPTR != pmut_limit);

    if (((uint64_t)0) == idx64) {
        *pmut_limit = ((uint32_t)0);
        return;
    }

    *pmut_limit = (uint32_t)((gdtr->base[idx64] & LIMIT_MASK1) >> LIMIT_SHIFT1) |
                  (uint32_t)((gdtr->base[idx64] & LIMIT_MASK2) >> LIMIT_SHIFT2);

    if (((uint64_t)0) != (gdtr->base[idx64] & GRANULARITY_BIT)) {
        *pmut_limit = (uint32_t)((((uint64_t)*pmut_limit) << LIMIT_SHIFTG) | LIMIT_MASKG);
    }
    else {
        bf_touch();
    }
}
