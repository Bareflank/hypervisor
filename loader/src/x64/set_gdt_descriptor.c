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

#include <debug.h>
#include <global_descriptor_table_register_t.h>
#include <types.h>

/** @brief defines the first set of bits associated with the attrib field */
#define ATTRIB_MASK1 ((uint64_t)0x0000FF0000000000)
/** @brief defines the second set of bits associated with the attrib field */
#define ATTRIB_MASK2 ((uint64_t)0x00F0000000000000)
/** @brief defines the bit location of the first set of attrib field */
#define ATTRIB_SHIFT1 ((uint64_t)40)
/** @brief defines the bit location of the second set of attrib field */
#define ATTRIB_SHIFT2 ((uint64_t)40)

/** @brief defines the first set of bits associated with the limit field */
#define LIMIT_MASK1 ((uint64_t)0x000000000000FFFF)
/** @brief defines the second set of bits associated with the limit field */
#define LIMIT_MASK2 ((uint64_t)0x000F000000000000)
/** @brief defines the bit location of the first set of limit field */
#define LIMIT_SHIFT1 ((uint64_t)0)
/** @brief defines the bit location of the second set of limit field */
#define LIMIT_SHIFT2 ((uint64_t)32)
/** @brief defines the bit location of the third set of limit field */
#define LIMIT_SHIFTG ((uint64_t)12)

/** @brief defines the first set of bits associated with the base field */
#define BASE_MASK1 ((uint64_t)0x00000000FFFF0000)
/** @brief defines the second set of bits associated with the base field */
#define BASE_MASK2 ((uint64_t)0x000000FF00000000)
/** @brief defines the third set of bits associated with the base field */
#define BASE_MASK3 ((uint64_t)0xFF00000000000000)
/** @brief defines the fourth set of bits associated with the base field */
#define BASE_MASK4 ((uint64_t)0x00000000FFFFFFFF)
/** @brief defines the bit location of the first set of base field */
#define BASE_SHIFT1 ((uint64_t)16)
/** @brief defines the bit location of the second set of base field */
#define BASE_SHIFT2 ((uint64_t)16)
/** @brief defines the bit location of the third set of base field */
#define BASE_SHIFT3 ((uint64_t)32)
/** @brief defines the bit location of the fourth set of base field */
#define BASE_SHIFT4 ((uint64_t)32)

/** @brief defines the bit location of the S bit in the attrib field */
#define SYSTEM_BIT ((uint64_t)0x0000100000000000)
/** @brief defines the bit location of the G bit in the attrib field */
#define GRANULARITY_BIT ((uint64_t)0x0080000000000000)

/**
 * <!-- description -->
 *   @brief Sets a GDT's descriptor given a selector into the GDT to
 *     set and the base, limit and attribute values to set the descriptor
 *     to. If the attribute flags set the global flag, the limit
 *
 * <!-- inputs/outputs -->
 *   @param gdtr a pointer to the gdtr that stores the GDT to set
 *   @param selector the selector of the descriptor in the provided GDT
 *     to get from
 *   @param base the base address to set the decriptor to in the provided GDT
 *     at the provided index
 *   @param limit the limit to set the decriptor to in the provided GDT
 *     at the provided index
 *   @param attrib the attributes to set the decriptor to in the provided GDT
 *     at the provided index
 *   @return 0 on success, LOADER_FAILURE on failure.
 */
int64_t
set_gdt_descriptor(
    struct global_descriptor_table_register_t const *const gdtr,
    uint16_t const selector,
    uint64_t const base,
    uint32_t const limit,
    uint16_t const attrib)
{
    uint64_t bytes64_0;
    uint64_t bytes64_1;

    uint64_t idx64_0 = (((uint64_t)selector) >> ((uint64_t)3)) + ((uint64_t)0);
    uint64_t idx64_1 = (((uint64_t)selector) >> ((uint64_t)3)) + ((uint64_t)1);

    uint64_t base64 = ((uint64_t)base);
    uint64_t limit64 = ((uint64_t)limit);
    uint64_t attrib64 = ((uint64_t)attrib);

    if (((void *)0) == gdtr) {
        bferror("invalid argument: gdtr == NULL");
        return LOADER_FAILURE;
    }

    bytes64_0 = ((uint64_t)gdtr->limit) + ((uint64_t)1);
    bytes64_1 = ((uint64_t)gdtr->limit) + ((uint64_t)1) - sizeof(uint64_t);

    if (((uint64_t)0) == idx64_0) {
        return LOADER_SUCCESS;
    }

    if (idx64_0 >= (bytes64_0 / sizeof(uint64_t))) {
        bferror("invalid argument: index into GDT is out of range");
        return LOADER_FAILURE;
    }

    if (((attrib64 << ATTRIB_SHIFT1) & SYSTEM_BIT) == ((uint64_t)0)) {
        if (idx64_1 >= (bytes64_1 / sizeof(uint64_t))) {
            bferror("invalid argument: index into GDT is out of range");
            return LOADER_FAILURE;
        }
    }

    if (((attrib64 << ATTRIB_SHIFT2) & GRANULARITY_BIT) != ((uint64_t)0)) {
        limit64 >>= LIMIT_SHIFTG;
    }

    gdtr->base[idx64_0] |= ((base64 << BASE_SHIFT1) & BASE_MASK1);
    gdtr->base[idx64_0] |= ((base64 << BASE_SHIFT2) & BASE_MASK2);
    gdtr->base[idx64_0] |= ((base64 << BASE_SHIFT3) & BASE_MASK3);
    gdtr->base[idx64_0] |= ((limit64 << LIMIT_SHIFT1) & LIMIT_MASK1);
    gdtr->base[idx64_0] |= ((limit64 << LIMIT_SHIFT2) & LIMIT_MASK2);
    gdtr->base[idx64_0] |= ((attrib64 << ATTRIB_SHIFT1) & ATTRIB_MASK1);
    gdtr->base[idx64_0] |= ((attrib64 << ATTRIB_SHIFT2) & ATTRIB_MASK2);

    if (((attrib64 << ATTRIB_SHIFT1) & SYSTEM_BIT) == ((uint64_t)0)) {
        gdtr->base[idx64_1] = ((base64 >> BASE_SHIFT4) & BASE_MASK4);
    }

    return LOADER_SUCCESS;
}
