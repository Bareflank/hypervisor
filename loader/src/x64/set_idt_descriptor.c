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
#include <interrupt_descriptor_table_register_t.h>
#include <types.h>

/** @brief defines the first set of bits associated with the attrib field */
#define ATTRIB_MASK1 ((uint64_t)0x0000FFFF00000000)
/** @brief defines the bit location of the first set of attrib field */
#define ATTRIB_SHIFT1 ((uint64_t)32)

/** @brief defines the first set of bits associated with the selector field */
#define SELECTOR_MASK1 ((uint64_t)0x00000000FFFF0000)
/** @brief defines the bit location of the first set of selector field */
#define SELECTOR_SHIFT1 ((uint64_t)16)

/** @brief defines the first set of bits associated with the offset field */
#define OFFSET_MASK1 ((uint64_t)0x000000000000FFFF)
/** @brief defines the second set of bits associated with the offset field */
#define OFFSET_MASK2 ((uint64_t)0xFFFF000000000000)
/** @brief defines the second set of bits associated with the offset field */
#define OFFSET_MASK3 ((uint64_t)0x00000000FFFFFFFF)
/** @brief defines the bit location of the first set of offset field */
#define OFFSET_SHIFT1 ((uint64_t)0)
/** @brief defines the bit location of the second set of offset field */
#define OFFSET_SHIFT2 ((uint64_t)32)
/** @brief defines the bit location of the third set of offset field */
#define OFFSET_SHIFT3 ((uint64_t)32)

/**
 * <!-- description -->
 *   @brief Sets an IDT's descriptor given an index into the IDT to
 *     set and the offset, selector and attribute values to set the descriptor
 *     to.
 *
 * <!-- inputs/outputs -->
 *   @param idtr a pointer to the idtr that stores the IDT to set
 *   @param idx the index of the descriptor in the provided IDT to set
 *   @param offset the offset to set the decriptor to in the provided IDT
 *     at the provided index
 *   @param selector the selector to set the decriptor to in the provided IDT
 *     at the provided index
 *   @param attrib the attributes to set the decriptor to in the provided IDT
 *     at the provided index
 *   @return 0 on success, LOADER_FAILURE on failure.
 */
int64_t
set_idt_descriptor(
    struct interrupt_descriptor_table_register_t const *const idtr,
    uint32_t const idx,
    uint64_t const offset,
    uint16_t const selector,
    uint16_t const attrib)
{
    uint64_t bytes64_0;
    uint64_t bytes64_1;

    uint64_t idx64_0 = (((uint64_t)idx) * ((uint64_t)2)) + ((uint64_t)0);
    uint64_t idx64_1 = (((uint64_t)idx) * ((uint64_t)2)) + ((uint64_t)1);

    uint64_t offset64 = ((uint64_t)offset);
    uint64_t selector64 = ((uint64_t)selector);
    uint64_t attrib64 = ((uint64_t)attrib);

    if (((void *)0) == idtr) {
        BFERROR("invalid argument: idtr == ((void *)0)\n");
        return LOADER_FAILURE;
    }

    bytes64_0 = ((uint64_t)idtr->limit) + ((uint64_t)1);
    bytes64_1 = ((uint64_t)idtr->limit) + ((uint64_t)1) - sizeof(uint64_t);

    if (idx64_0 >= (bytes64_0 / sizeof(uint64_t))) {
        BFERROR("invalid argument: index into GDT is out of range\n");
        return LOADER_FAILURE;
    }

    if (idx64_1 >= (bytes64_1 / sizeof(uint64_t))) {
        BFERROR("invalid argument: index into GDT is out of range\n");
        return LOADER_FAILURE;
    }

    idtr->base[idx64_0] |= ((offset64 << OFFSET_SHIFT1) & OFFSET_MASK1);
    idtr->base[idx64_0] |= ((offset64 << OFFSET_SHIFT2) & OFFSET_MASK2);
    idtr->base[idx64_1] |= ((offset64 >> OFFSET_SHIFT3) & OFFSET_MASK3);
    idtr->base[idx64_0] |= ((selector64 << SELECTOR_SHIFT1) & SELECTOR_MASK1);
    idtr->base[idx64_0] |= ((attrib64 << ATTRIB_SHIFT1) & ATTRIB_MASK1);

    return LOADER_SUCCESS;
}
