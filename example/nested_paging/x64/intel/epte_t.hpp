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

#ifndef EPTE_T_HPP
#define EPTE_T_HPP

#include <bsl/convert.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/safe_integral.hpp>

#pragma pack(push, 1)

namespace example
{
    /// @struct example::epte_t
    /// <!-- description -->
    ///   @brief Defines the layout of a nested page table entry (EPTE).
    ///
    struct epte_t final
    {
        /// @brief defines the "read access" field in the page
        bsl::uint64 r : static_cast<bsl::uint64>(1);
        /// @brief defines the "write access" field in the page
        bsl::uint64 w : static_cast<bsl::uint64>(1);
        /// @brief defines the "execute access" field in the page
        bsl::uint64 e : static_cast<bsl::uint64>(1);
        /// @brief defines the "memory type" field in the page
        bsl::uint64 type : static_cast<bsl::uint64>(3);
        /// @brief defines the "ignore pat" field in the page
        bsl::uint64 ignore_pat : static_cast<bsl::uint64>(1);
        /// @brief defines the "ignored" field in the page
        bsl::uint64 ignored1 : static_cast<bsl::uint64>(1);
        /// @brief defines the "accessed" field in the page
        bsl::uint64 a : static_cast<bsl::uint64>(1);
        /// @brief defines the "ignored" field in the page
        bsl::uint64 d : static_cast<bsl::uint64>(1);
        /// @brief defines the "user execute access" field in the page
        bsl::uint64 e_user : static_cast<bsl::uint64>(1);
        /// @brief defines the "ignored" field in the page
        bsl::uint64 ignored2 : static_cast<bsl::uint64>(1);
        /// @brief defines the "physical address" field in the page
        bsl::uint64 phys : static_cast<bsl::uint64>(40);
        /// @brief defines the "ignored" field in the page
        bsl::uint64 ignored3 : static_cast<bsl::uint64>(9);
        /// @brief defines the "sub page write permissions" field in the page
        bsl::uint64 sub : static_cast<bsl::uint64>(1);
        /// @brief defines the "ignored" field in the page
        bsl::uint64 ignored4 : static_cast<bsl::uint64>(1);
        /// @brief defines the "virtualization exception" field in the page
        bsl::uint64 ve : static_cast<bsl::uint64>(1);
    };
}

#pragma pack(pop)

#endif
