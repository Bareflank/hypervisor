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

#ifndef PT_T_HPP
#define PT_T_HPP

#include <pte_t.hpp>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>

#pragma pack(push, 1)

namespace mk
{
    /// @brief defined the expected size of the pt_t struct
    constexpr bsl::safe_uintmax NUM_PT_ENTRIES{bsl::to_umax(512)};

    /// @struct mk::pt_t
    ///
    /// <!-- description -->
    ///   @brief Defines the layout of a page table (pt).
    ///
    struct pt_t final
    {
        /// @brief stores the entires in the table
        bsl::array<loader::pte_t, NUM_PT_ENTRIES.get()> entries;
    };

    namespace details
    {
        /// @brief defined the expected size of the pt_t struct
        constexpr bsl::safe_uintmax EXPECTED_PT_T_SIZE{bsl::to_umax(HYPERVISOR_PAGE_SIZE)};

        /// Check to make sure the pt_t is the right size.
        static_assert(sizeof(pt_t) == EXPECTED_PT_T_SIZE);
    }
}

#pragma pack(pop)

#endif
