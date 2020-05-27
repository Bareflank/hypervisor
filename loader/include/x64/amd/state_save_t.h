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

#ifndef STATE_SAVE_T
#define STATE_SAVE_T

#pragma pack(push, 1)

#include <loader_types.h>

/**
 * @class state_save_t
 *
 * <!-- description -->
 *   @brief The following defines the structure of the state save area for
 *     the guest and the host. For the guest, we need to store state that
 *     the VMRUN function does not save for us. For the host, we need to
 *     provide a page of memory that the VMRUN function can save to as it
 *     sees fit. Since we do not know what the format of the state save is
 *     on AMD and you are not allowed to touch the host's state save area,
 *     on the host, this structure only serves to reseve memory. The fields
 *     only make sense for the guest.
 */
struct state_save_t
{
    // -------------------------------------------------------------------------
    // General Purpose Registers
    // -------------------------------------------------------------------------

    uint64_t rcx;    ///< offset 0x000
    uint64_t rdx;    ///< offset 0x008
    uint64_t rbx;    ///< offset 0x010
    uint64_t rbp;    ///< offset 0x018
    uint64_t rdi;    ///< offset 0x020
    uint64_t rsi;    ///< offset 0x028
    uint64_t r8;     ///< offset 0x030
    uint64_t r9;     ///< offset 0x038
    uint64_t r10;    ///< offset 0x040
    uint64_t r11;    ///< offset 0x048
    uint64_t r12;    ///< offset 0x050
    uint64_t r13;    ///< offset 0x058
    uint64_t r14;    ///< offset 0x060
    uint64_t r15;    ///< offset 0x068

    // -------------------------------------------------------------------------
    // Debug Registers
    // -------------------------------------------------------------------------

    uint64_t dr0;    ///< offset 0x070
    uint64_t dr1;    ///< offset 0x078
    uint64_t dr2;    ///< offset 0x080
    uint64_t dr3;    ///< offset 0x088

    // -------------------------------------------------------------------------
    // Control Registers
    // -------------------------------------------------------------------------

    uint64_t cr8;    ///< offset 0x090

    // -------------------------------------------------------------------------
    // SSE / Floating Point
    // -------------------------------------------------------------------------

    uint64_t xcr0;                ///< offset 0x098
    uint8_t reserved13[0xF60];    ///< offset 0x100
};

_Static_assert(sizeof(struct state_save_t) == 0x1000, "");

#pragma pack(pop)

#endif
