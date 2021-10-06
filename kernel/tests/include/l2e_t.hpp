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

#ifndef L2E_T_HPP
#define L2E_T_HPP

#include <bsl/cstdint.hpp>

#pragma pack(push, 1)

namespace lib
{
    /// <!-- description -->
    ///   @brief Defines the layout of the level-2 table entry (l2e).
    ///
    struct l2e_t final
    {
        /// @brief reserved
        bsl::uint64 reserved1 : static_cast<bsl::uint64>(7);
        /// @brief defines our "present" field in the page
        bsl::uint64 p : static_cast<bsl::uint64>(1);
        /// @brief defines our "unknown" field in the page
        bsl::uint64 u : static_cast<bsl::uint64>(1);
        /// @brief defines our "auto_release" field in the page
        bsl::uint64 auto_release : static_cast<bsl::uint64>(1);
        /// @brief defines the "points_to_block" field in the page
        bsl::uint64 points_to_block : static_cast<bsl::uint64>(1);
        /// @brief defines our "aliased" field in the page
        bsl::uint64 alias : static_cast<bsl::uint64>(1);
        /// @brief defines the "physical address" field in the page
        bsl::uint64 phys : static_cast<bsl::uint64>(40);
        /// @brief defines our "explicit_unmap" field in the page
        bsl::uint64 explicit_unmap : static_cast<bsl::uint64>(1);
        /// @brief reserved
        bsl::uint64 reserved2 : static_cast<bsl::uint64>(11);
    };
}

#pragma pack(pop)

#endif
