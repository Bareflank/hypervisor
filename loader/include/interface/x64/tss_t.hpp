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

#ifndef TSS_T_HPP
#define TSS_T_HPP

#include <bsl/cstdint.hpp>

#pragma pack(push, 1)

namespace loader
{
    /// <!-- description -->
    ///   @brief Defines the structure of the task state segment
    ///     as defined by the AMD SDM.
    ///
    struct tss_t final
    {
        /// @brief reserved
        bsl::uint32 reserved1;
        /// @brief stores the rsp for privilege level 0
        bsl::uint64 rsp0;
        /// @brief stores the rsp for privilege level 1
        bsl::uint64 rsp1;
        /// @brief stores the rsp for privilege level 2
        bsl::uint64 rsp2;
        /// @brief reserved
        bsl::uint32 reserved2;
        /// @brief reserved
        bsl::uint32 reserved3;
        /// @brief stores the address of the interrupt-stack-table pointer #1
        bsl::uint64 ist1;
        /// @brief stores the address of the interrupt-stack-table pointer #2
        bsl::uint64 ist2;
        /// @brief stores the address of the interrupt-stack-table pointer #3
        bsl::uint64 ist3;
        /// @brief stores the address of the interrupt-stack-table pointer #4
        bsl::uint64 ist4;
        /// @brief stores the address of the interrupt-stack-table pointer #5
        bsl::uint64 ist5;
        /// @brief stores the address of the interrupt-stack-table pointer #6
        bsl::uint64 ist6;
        /// @brief stores the address of the interrupt-stack-table pointer #7
        bsl::uint64 ist7;
        /// @brief reserved
        bsl::uint32 reserved4;
        /// @brief reserved
        bsl::uint32 reserved5;
        /// @brief reserved
        bsl::uint16 reserved6;
        /// @brief stores the offset to the IO map base address
        bsl::uint16 iomap;
    };
}

#pragma pack(pop)

#endif
