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

#ifndef PTE_T_HPP
#define PTE_T_HPP

#pragma pack(push, 1)

#include <bsl/convert.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/safe_integral.hpp>

namespace loader
{
    /// @struct loader::pte_t
    /// <!-- description -->
    ///   @brief Defines the layout of a page table entry (PTE).
    ///
    struct pte_t final
    {
        /// @brief defines the "present" field in the page
        bsl::uint64 p : static_cast<bsl::uint64>(1);
        /// @brief defines the "read/write" field in the page
        bsl::uint64 rw : static_cast<bsl::uint64>(1);
        /// @brief defines the "user/supervisor" field in the page
        bsl::uint64 us : static_cast<bsl::uint64>(1);
        /// @brief defines the "page-level writethrough" field in the page
        bsl::uint64 pwt : static_cast<bsl::uint64>(1);
        /// @brief defines the "page-level cache disable" field in the page
        bsl::uint64 pcd : static_cast<bsl::uint64>(1);
        /// @brief defines the "accessed" field in the page
        bsl::uint64 a : static_cast<bsl::uint64>(1);
        /// @brief defines the "dirty" field in the page
        bsl::uint64 d : static_cast<bsl::uint64>(1);
        /// @brief defines the "page-attribute table" field in the page
        bsl::uint64 pat : static_cast<bsl::uint64>(1);
        /// @brief defines the "global page" field in the page
        bsl::uint64 g : static_cast<bsl::uint64>(1);
        /// @brief defines the "available to software" field in the page
        bsl::uint64 avl : static_cast<bsl::uint64>(3);
        /// @brief defines the physical addressfield in the page
        bsl::uint64 phys : static_cast<bsl::uint64>(40);
        /// @brief defines whether or not the page can be auto released
        bsl::uint64 auto_release : static_cast<bsl::uint64>(7);
        /// @brief defines the "memory protection key" field in the page
        bsl::uint64 mpk : static_cast<bsl::uint64>(4);
        /// @brief defines the "no-execute" field in the page
        bsl::uint64 nx : static_cast<bsl::uint64>(1);
    };

    namespace details
    {
        /// @brief defined the expected size of the pte_t struct
        constexpr bsl::safe_uintmax EXPECTED_PTE_T_SIZE{bsl::to_umax(8)};

        /// Check to make sure the pte_t is the right size.
        static_assert(sizeof(pte_t) == EXPECTED_PTE_T_SIZE);
    }
}

#pragma pack(pop)

#endif
