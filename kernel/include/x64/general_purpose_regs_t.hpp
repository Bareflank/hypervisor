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

#ifndef GENERAL_PURPOSE_REGS_T_HPP
#define GENERAL_PURPOSE_REGS_T_HPP

#include <bsl/cstdint.hpp>

#pragma pack(push, 1)

namespace mk
{
    /// @struct mk::general_purpose_regs_t
    ///
    /// <!-- description -->
    ///   @brief Stores the state of the general purpose registers. Note
    ///     that this storage is only used when swapping from one VS to
    ///     another. Otherwise, an extension's TLS block is used instead
    ///     to access the general purpose registers as they are faster.
    ///
    struct general_purpose_regs_t final
    {
        /// @brief stores the value of rax (0x000)
        bsl::uint64 rax;
        /// @brief stores the value of rbx (0x008)
        bsl::uint64 rbx;
        /// @brief stores the value of rcx (0x010)
        bsl::uint64 rcx;
        /// @brief stores the value of rdx (0x018)
        bsl::uint64 rdx;
        /// @brief stores the value of rbp (0x020)
        bsl::uint64 rbp;
        /// @brief stores the value of rsi (0x028)
        bsl::uint64 rsi;
        /// @brief stores the value of rdi (0x030)
        bsl::uint64 rdi;
        /// @brief stores the value of r8 (0x038)
        bsl::uint64 r8;
        /// @brief stores the value of r9 (0x040)
        bsl::uint64 r9;
        /// @brief stores the value of r10 (0x048)
        bsl::uint64 r10;
        /// @brief stores the value of r11 (0x050)
        bsl::uint64 r11;
        /// @brief stores the value of r12 (0x058)
        bsl::uint64 r12;
        /// @brief stores the value of r13 (0x060)
        bsl::uint64 r13;
        /// @brief stores the value of r14 (0x068)
        bsl::uint64 r14;
        /// @brief stores the value of r15 (0x070)
        bsl::uint64 r15;
    };
}

#pragma pack(pop)

#endif
