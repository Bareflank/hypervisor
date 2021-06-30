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

#ifndef L2TE_T
#define L2TE_T

#include <bsl/cstdint.hpp>

#pragma pack(push, 1)

namespace mk
{
    /// @struct mk::l2te_t
    ///
    /// <!-- description -->
    ///   @brief Defines the layout of a level-2 table entry (L2TE).
    ///
    struct l2te_t final
    {
        /// @brief defines the "present" field in the page
        bsl::uint64 p : static_cast<bsl::uint64>(1);
        /// @brief defines the "block/table" field in the page
        bsl::uint64 bt : static_cast<bsl::uint64>(1);
        /// @brief defines the "available to software" field in the page
        bsl::uint64 available1 : static_cast<bsl::uint64>(10);
        /// @brief defines the "physical address" field in the page
        bsl::uint64 phys : static_cast<bsl::uint64>(40);
        /// @brief defines the "available to software" field in the page
        bsl::uint64 available2 : static_cast<bsl::uint64>(7);
        /// @brief defines the "PXNTable" field in the page
        bsl::uint64 pxntable : static_cast<bsl::uint64>(1);
        /// @brief defines the "XNTable" field in the page
        bsl::uint64 xntable : static_cast<bsl::uint64>(1);
        /// @brief defines the "APTable" field in the page
        bsl::uint64 aptable : static_cast<bsl::uint64>(2);
        /// @brief defines the "NSTable" field in the page
        bsl::uint64 nstable : static_cast<bsl::uint64>(1);
    };
}

#pragma pack(pop)

#endif
