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

#ifndef L3TE_T
#define L3TE_T

#include <bsl/cstdint.hpp>

#pragma pack(push, 1)

namespace mk
{
    /// <!-- description -->
    ///   @brief Defines the layout of a level-3 table entry (L3TE).
    ///
    struct l3te_t final
    {
        /// @brief defines the "present" field in the page
        bsl::uint64 p : static_cast<bsl::uint64>(1);
        /// @brief defines the "page" field in the page
        bsl::uint64 page : static_cast<bsl::uint64>(1);
        /// @brief defines the "AttrIndx" field in the page
        bsl::uint64 attr_indx : static_cast<bsl::uint64>(3);
        /// @brief defines the "NS" field in the page
        bsl::uint64 ns : static_cast<bsl::uint64>(1);
        /// @brief defines the "AP" field in the page
        bsl::uint64 ap : static_cast<bsl::uint64>(2);
        /// @brief defines the "SH" field in the page
        bsl::uint64 sh : static_cast<bsl::uint64>(2);
        /// @brief defines the "AF" field in the page
        bsl::uint64 af : static_cast<bsl::uint64>(1);
        /// @brief defines the "nG" field in the page
        bsl::uint64 ng : static_cast<bsl::uint64>(1);
        /// @brief defines the "physical address" field in the page
        bsl::uint64 phys : static_cast<bsl::uint64>(38);
        /// @brief defines the "GP" field in the page
        bsl::uint64 gp : static_cast<bsl::uint64>(1);
        /// @brief defines the "DBM" field in the page
        bsl::uint64 dbm : static_cast<bsl::uint64>(1);
        /// @brief defines the "Contiguous" field in the page
        bsl::uint64 contiguous : static_cast<bsl::uint64>(1);
        /// @brief defines the "PXN" field in the page
        bsl::uint64 pxn : static_cast<bsl::uint64>(1);
        /// @brief defines the "UXN or XN" field in the page
        bsl::uint64 xn : static_cast<bsl::uint64>(1);
        /// @brief defines our "auto_release" field in the page
        bsl::uint64 auto_release : static_cast<bsl::uint64>(3);
        /// @brief defines the "available to software" field in the page
        bsl::uint64 available1 : static_cast<bsl::uint64>(1);
        /// @brief defines the "PBHA" field in the page
        bsl::uint64 pbha : static_cast<bsl::uint64>(4);
        /// @brief defines the "available to software" field in the page
        bsl::uint64 available2 : static_cast<bsl::uint64>(1);
    };
}

#pragma pack(pop)

#endif
