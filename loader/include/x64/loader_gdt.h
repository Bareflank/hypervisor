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

#ifndef LOADER_GDT_H
#define LOADER_GDT_H

#pragma pack(push, 1)

#include <loader_debug.h>
#include <loader_types.h>

/**
 * @struct segment_descriptor
 *
 * <!-- description -->
 *   @brief Defines the structure of a segment descriptor as defined by the
 *     AMD SDM.
 */
struct segment_descriptor
{
    /** @brief stores bits 0-15 of the segment's limit */
    uint32_t limit15_00 : 16U;
    /** @brief stores bits 0-15 of the segment's base address */
    uint32_t base15_00 : 16U;
    /** @brief stores bits 16-23 of the segment's base address */
    uint32_t base23_16 : 8U;
    /** @brief stores bits 0-7 of the segment's attributes */
    uint32_t attrib07_00 : 8U;
    /** @brief stores bits 16-19 of the segment's limit */
    uint32_t limit19_16 : 4U;
    /** @brief stores bits 8-11 of the segment's attributes */
    uint32_t attrib11_08 : 4U;
    /** @brief stores bits 24-31 of the segment's base address */
    uint32_t base31_24 : 8U;
};

/**
 * @class global_descriptor_table_register
 *
 * <!-- description -->
 *   @brief Defines the structure of the global descriptor table register
 *     as defined by the AMD SDM.
 */
struct global_descriptor_table_register
{
    /** @brief stores the size of the gdtr in bytes (minus 1) */
    uint16_t limit;
    /** @brief stores a pointer to the gdtr */
    struct segment_descriptor *base;
};

/**
 * <!-- description -->
 *   @brief Returns a segment descriptor's attribute flags, all shifted to
 *     the right as much as possible, producing a 12 bit value that can be
 *     used to initialize a segment's hidden attribute register.
 *
 * <!-- inputs/outputs -->
 *   @param gdtr a pointer to the gdtr to get the attributes from
 *   @param index the index of the segment descriptor in the provided gdtr
 *     to get the attributes from.
 *   @return Returns the requested attributes on success, otherwise returns
 *     all F's, indicating an invalid attribute value.
 */
static inline uint32_t
get_segment_descriptor_attrib(
    struct global_descriptor_table_register const *const gdtr, uint16_t const index)
{
    if (NULL == gdtr) {
        BFERROR("invalid argument: gdtr == NULL\n");
        return 0xFFFFFFFFU;
    }

    if (0 == index) {
        return 0U;
    }

    if (index >= ((gdtr->limit + 1) / sizeof(struct segment_descriptor))) {
        BFERROR("invalid argument: index into GDT is out of range\n");
        return 0xFFFFFFFFU;
    }

    /**
     * Notes:
     * - Unlike the limit, this function does not mimic the LAR instr,
     *   and instead, returns the result that the hypevisor's VMCS/VMCB
     *   is expecting. Instead of just masking off the non-AR bits in
     *   the descriptor, the hidden register that the hypervisor has
     *   to populate are all of the access rights, in the same order
     *   they appear in the descriptor, but shifted right as much as
     *   possible to remove all of the non-AR bits, producing a 12 bit
     *   field. Like the limit, I have not been able to find some docs
     *   for this, other than to say... this is how it works.
     */

    return (gdtr->base[index].attrib11_08 << 8U) |    // --
           (gdtr->base[index].attrib07_00 << 0U);
}

/**
 * <!-- description -->
 *   @brief Returns a segment descriptor's limit in bytes.
 *
 * <!-- inputs/outputs -->
 *   @param gdtr a pointer to the gdtr to get the limit from
 *   @param index the index of the segment descriptor in the provided gdtr
 *     to get the limit from.
 *   @return Returns the requested limit on success, otherwise returns
 *     0, indicating an invalid limit.
 */
static inline uint32_t
get_segment_descriptor_limit(
    struct global_descriptor_table_register const *const gdtr, uint16_t const index)
{
    if (NULL == gdtr) {
        BFERROR("invalid argument: gdtr == NULL\n");
        return 0;
    }

    if (0 == index) {
        return 0U;
    }

    if (index >= ((gdtr->limit + 1) / sizeof(struct segment_descriptor))) {
        BFERROR("invalid argument: index into GDT is out of range\n");
        return 0;
    }

    /**
     * Notes:
     * - The lsl instruction returns the limit with the granularity
     *   bit in mind. Specifically, if the granularity bit is set, the
     *   limit is in 4k blocks. To convert it to bytes, we need to shift
     *   it by 12 and or with 0xFFF. The hypevisor itself sets the
     *   hidden portion of the segment registers which requires that
     *   the limit is in bytes (although I have not been able to find
     *   documentation on this, that is what it is looking for). If you
     *   do not do this, when the OS switches to compatibility mode to
     *   run 32bit apps, the limit will be used again, and will be off
     *   by a factor of 4k.
     */

    if ((gdtr->base[index].attrib11_08 & 0x8) != 0) {
        return (gdtr->base[index].limit19_16 << 28U) |    // --
               (gdtr->base[index].limit15_00 << 12U) |    // --
               (0x00000FFF);
    }
    else {
        return (gdtr->base[index].limit19_16 << 16U) |    // --
               (gdtr->base[index].limit15_00 << 0U);
    }
}

/**
 * <!-- description -->
 *   @brief Returns a segment descriptor's base address.
 *
 * <!-- inputs/outputs -->
 *   @param gdtr a pointer to the gdtr to get the base address from
 *   @param index the index of the segment descriptor in the provided gdtr
 *     to get the base address from.
 *   @return Returns the requested base address on success, otherwise returns
 *     all F's, indicating an invalid base address.
 */
static inline uint32_t
get_segment_descriptor_base(
    struct global_descriptor_table_register const *const gdtr, uint16_t const index)
{
    if (NULL == gdtr) {
        BFERROR("invalid argument: gdtr == NULL\n");
        return 0xFFFFFFFFU;
    }

    if (0 == index) {
        return 0U;
    }

    if (index >= ((gdtr->limit + 1) / sizeof(struct segment_descriptor))) {
        BFERROR("invalid argument: index into GDT is out of range\n");
        return 0xFFFFFFFFU;
    }

    return (gdtr->base[index].base31_24 << 24U) |    // --
           (gdtr->base[index].base23_16 << 16U) |    // --
           (gdtr->base[index].base15_00 << 0U);
}

#pragma pack(pop)

#endif
