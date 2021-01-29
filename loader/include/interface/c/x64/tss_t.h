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

#ifndef TSS_T_H
#define TSS_T_H

#include <constants.h>
#include <static_assert.h>
#include <types.h>

#pragma pack(push, 1)

/**
 * @struct tss_t
 *
 * <!-- description -->
 *   @brief Defines the structure of the task state segment
 *     as defined by the AMD SDM.
 */
struct tss_t
{
    /** @brief reserved (0x000) */
    uint32_t reserved1;
    /** @brief rsp for privilege level 0 (0x004) */
    uint64_t rsp0;
    /** @brief rsp for privilege level 1 (0x00C) */
    uint64_t rsp1;
    /** @brief rsp for privilege level 2 (0x014) */
    uint64_t rsp2;
    /** @brief reserved (0x01C) */
    uint32_t reserved2;
    /** @brief reserved (0x020) */
    uint32_t reserved3;
    /** @brief address of the interrupt-stack-table pointer #1 (0x024) */
    uint64_t ist1;
    /** @brief address of the interrupt-stack-table pointer #2 (0x02C) */
    uint64_t ist2;
    /** @brief address of the interrupt-stack-table pointer #3 (0x034) */
    uint64_t ist3;
    /** @brief address of the interrupt-stack-table pointer #4 (0x03C) */
    uint64_t ist4;
    /** @brief address of the interrupt-stack-table pointer #5 (0x044) */
    uint64_t ist5;
    /** @brief address of the interrupt-stack-table pointer #6 (0x04C) */
    uint64_t ist6;
    /** @brief address of the interrupt-stack-table pointer #7 (0x054) */
    uint64_t ist7;
    /** @brief reserved (0x05C) */
    uint32_t reserved4;
    /** @brief reserved (0x060) */
    uint32_t reserved5;
    /** @brief reserved (0x064) */
    uint16_t reserved6;
    /** @brief offset to the IO map base address (0x066) */
    uint16_t iomap;
};

/** @brief Check to make sure the state_save_t is the right size. */
STATIC_ASSERT(sizeof(struct tss_t) <= HYPERVISOR_PAGE_SIZE, invalid_size);

#pragma pack(pop)

#endif
