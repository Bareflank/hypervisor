/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// @copyright
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// @copyright
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#ifndef STATE_SAVE_T_HPP
#define STATE_SAVE_T_HPP

#include <bsl/convert.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/details/carray.hpp>
#include <bsl/safe_integral.hpp>

#pragma pack(push, 1)

namespace loader
{
    /// @brief the size of reserved #0 in the state_save_t
    constexpr auto SS_RESERVED0_SIZE{0xE_umax};
    /// @brief the size of reserved #1 in the state_save_t
    constexpr auto SS_RESERVED1_SIZE{0xA_umax};

    /// @struct loader::state_save_t
    ///
    /// <!-- description -->
    ///   @brief Stores the registers and processor state that is used by the
    ///     microkernel that must be restored in the event of an error or the
    ///     successful launch of the hypervisor.
    ///
    struct state_save_t final
    {
        /// --------------------------------------------------------------------
        /// General Purpose Registers
        /// --------------------------------------------------------------------

        /// @brief stores the value of x0 (0x000)
        bsl::uint64 x0;
        /// @brief stores the value of x1 (0x008)
        bsl::uint64 x1;
        /// @brief stores the value of x2 (0x010)
        bsl::uint64 x2;
        /// @brief stores the value of x3 (0x018)
        bsl::uint64 x3;
        /// @brief stores the value of x4 (0x020)
        bsl::uint64 x4;
        /// @brief stores the value of x5 (0x028)
        bsl::uint64 x5;
        /// @brief stores the value of x6 (0x030)
        bsl::uint64 x6;
        /// @brief stores the value of x7 (0x038)
        bsl::uint64 x7;
        /// @brief stores the value of x8 (0x040)
        bsl::uint64 x8;
        /// @brief stores the value of x9 (0x048)
        bsl::uint64 x9;
        /// @brief stores the value of x10 (0x050)
        bsl::uint64 x10;
        /// @brief stores the value of x11 (0x058)
        bsl::uint64 x11;
        /// @brief stores the value of x12 (0x060)
        bsl::uint64 x12;
        /// @brief stores the value of x13 (0x068)
        bsl::uint64 x13;
        /// @brief stores the value of x14 (0x070)
        bsl::uint64 x14;
        /// @brief stores the value of x15 (0x078)
        bsl::uint64 x15;
        /// @brief stores the value of x16 (0x080)
        bsl::uint64 x16;
        /// @brief stores the value of x17 (0x088)
        bsl::uint64 x17;
        /// @brief stores the value of x18 (0x090)
        bsl::uint64 x18;
        /// @brief stores the value of x19 (0x098)
        bsl::uint64 x19;
        /// @brief stores the value of x20 (0x0A0)
        bsl::uint64 x20;
        /// @brief stores the value of x21 (0x0A8)
        bsl::uint64 x21;
        /// @brief stores the value of x22 (0x0B0)
        bsl::uint64 x22;
        /// @brief stores the value of x23 (0x0B8)
        bsl::uint64 x23;
        /// @brief stores the value of x24 (0x0C0)
        bsl::uint64 x24;
        /// @brief stores the value of x25 (0x0C8)
        bsl::uint64 x25;
        /// @brief stores the value of x26 (0x0D0)
        bsl::uint64 x26;
        /// @brief stores the value of x27 (0x0D8)
        bsl::uint64 x27;
        /// @brief stores the value of x28 (0x0E0)
        bsl::uint64 x28;
        /// @brief stores the value of x29 (0x0E8)
        bsl::uint64 x29;
        /// @brief stores the value of x30 (0x0F0)
        bsl::uint64 x30;
        /// @brief stores the value of sp_el2 (0x0F8)
        bsl::uint64 sp_el2;
        /// @brief stores the value of pc_el2 (0x100)
        bsl::uint64 pc_el2;

        /// --------------------------------------------------------------------
        /// Saved Program Status Registers (SPSR)
        /// --------------------------------------------------------------------

        /// @brief stores the value of daif (0x108)
        bsl::uint64 daif;
        /// @brief stores the value of spsel (0x110)
        bsl::uint64 spsel;

        /// @brief reserved for future use (0x118)
        bsl::details::carray<bsl::uint64, SS_RESERVED0_SIZE.get()> reserved0;

        /// --------------------------------------------------------------------
        /// Exceptions
        /// --------------------------------------------------------------------

        /// @brief stores the value of vbar_el2 (0x188)
        bsl::uint64 vbar_el2;

        /// --------------------------------------------------------------------
        /// System Registers
        /// --------------------------------------------------------------------

        /// @brief stores the value of hcr_el2 (0x190)
        bsl::uint64 hcr_el2;
        /// @brief stores the value of mair_el2 (0x198)
        bsl::uint64 mair_el2;
        /// @brief stores the value of sctlr_el2 (0x1A0)
        bsl::uint64 sctlr_el2;
        /// @brief stores the value of tcr_el2 (0x1A8)
        bsl::uint64 tcr_el2;
        /// @brief stores the value of ttbr0_el2 (0x1B0)
        bsl::uint64 ttbr0_el2;
        /// @brief stores the value of tpidr_el2 (0x1B8)
        bsl::uint64 tpidr_el2;

        /// @brief reserved for future use (0x1C0)
        bsl::details::carray<bsl::uint64, SS_RESERVED1_SIZE.get()> reserved1;

        /// --------------------------------------------------------------------
        /// Handlers
        /// --------------------------------------------------------------------

        /// @brief stores the promote handler (0x210)
        void *promote_handler;
        /// @brief stores the exception vectors (0x218)
        void *exception_vectors;
    };
}

#pragma pack(pop)

#endif
