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

#ifndef STATE_SAVE_T_H
#define STATE_SAVE_T_H

#include <types.h>

#pragma pack(push, 1)

/**
 * <!-- description -->
 *   @brief Stores the registers and processor state that is used by the
 *     microkernel that must be restored in the event of an error or the
 *     successful launch of the hypervisor.
 */
struct state_save_t
{
    /**************************************************************************/
    /* General Purpose Registers                                              */
    /**************************************************************************/

    /** @brief stores the value of x0 (0x000) */
    uint64_t x0;
    /** @brief stores the value of x1 (0x008) */
    uint64_t x1;
    /** @brief stores the value of x2 (0x010) */
    uint64_t x2;
    /** @brief stores the value of x3 (0x018) */
    uint64_t x3;
    /** @brief stores the value of x4 (0x020) */
    uint64_t x4;
    /** @brief stores the value of x5 (0x028) */
    uint64_t x5;
    /** @brief stores the value of x6 (0x030) */
    uint64_t x6;
    /** @brief stores the value of x7 (0x038) */
    uint64_t x7;
    /** @brief stores the value of x8 (0x040) */
    uint64_t x8;
    /** @brief stores the value of x9 (0x048) */
    uint64_t x9;
    /** @brief stores the value of x10 (0x050) */
    uint64_t x10;
    /** @brief stores the value of x11 (0x058) */
    uint64_t x11;
    /** @brief stores the value of x12 (0x060) */
    uint64_t x12;
    /** @brief stores the value of x13 (0x068) */
    uint64_t x13;
    /** @brief stores the value of x14 (0x070) */
    uint64_t x14;
    /** @brief stores the value of x15 (0x078) */
    uint64_t x15;
    /** @brief stores the value of x16 (0x080) */
    uint64_t x16;
    /** @brief stores the value of x17 (0x088) */
    uint64_t x17;
    /** @brief stores the value of x18 (0x090) */
    uint64_t x18;
    /** @brief stores the value of x19 (0x098) */
    uint64_t x19;
    /** @brief stores the value of x20 (0x0A0) */
    uint64_t x20;
    /** @brief stores the value of x21 (0x0A8) */
    uint64_t x21;
    /** @brief stores the value of x22 (0x0B0) */
    uint64_t x22;
    /** @brief stores the value of x23 (0x0B8) */
    uint64_t x23;
    /** @brief stores the value of x24 (0x0C0) */
    uint64_t x24;
    /** @brief stores the value of x25 (0x0C8) */
    uint64_t x25;
    /** @brief stores the value of x26 (0x0D0) */
    uint64_t x26;
    /** @brief stores the value of x27 (0x0D8) */
    uint64_t x27;
    /** @brief stores the value of x28 (0x0E0) */
    uint64_t x28;
    /** @brief stores the value of x29 (0x0E8) */
    uint64_t x29;
    /** @brief stores the value of x30 (0x0F0) */
    uint64_t x30;
    /** @brief stores the value of sp_el2 (0x0F8) */
    uint64_t sp_el2;
    /** @brief stores the value of pc_el2 (0x100) */
    uint64_t pc_el2;

    /**************************************************************************/
    /* Saved Program Status Registers (SPSR)                                  */
    /**************************************************************************/

    /** @brief stores the value of daif (0x108) */
    uint64_t daif;
    /** @brief stores the value of spsel (0x110) */
    uint64_t spsel;

    /** @brief reserved for future use (0x118) */
    uint64_t reserved0[0xE];

    /**************************************************************************/
    /* Exceptions                                                             */
    /**************************************************************************/

    /** @brief stores the value of vbar_el2 (0x188) */
    uint64_t vbar_el2;

    /**************************************************************************/
    /* System Registers                                                       */
    /**************************************************************************/

    /** @brief stores the value of hcr_el2 (0x190) */
    uint64_t hcr_el2;
    /** @brief stores the value of mair_el2 (0x198) */
    uint64_t mair_el2;
    /** @brief stores the value of sctlr_el2 (0x1A0) */
    uint64_t sctlr_el2;
    /** @brief stores the value of tcr_el2 (0x1A8) */
    uint64_t tcr_el2;
    /** @brief stores the value of ttbr0_el2 (0x1B0) */
    uint64_t ttbr0_el2;
    /** @brief stores the value of tpidr_el2 (0x1B8) */
    uint64_t tpidr_el2;

    /** @brief reserved for future use (0x1C0) */
    uint64_t reserved1[0xA];

    /**************************************************************************/
    /* Handlers                                                               */
    /**************************************************************************/

    /** @brief stores the promote handler (0x210) */
    void *promote_handler;
    /** @brief stores the exception vectors (0x218) */
    void *exception_vectors;
};

#pragma pack(pop)

#endif
