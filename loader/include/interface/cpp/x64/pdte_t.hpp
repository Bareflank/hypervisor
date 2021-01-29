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

#ifndef PDTE_T_HPP
#define PDTE_T_HPP

#pragma pack(push, 1)

#include <bsl/convert.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/safe_integral.hpp>

namespace loader
{
    /// @struct loader::pdte_t
    ///
    /// <!-- description -->
    ///   @brief Defines the layout of a page-directory table entry (PDTE).
    ///
    struct pdte_t final
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
        /// @brief defines an ignored field in the page
        bsl::uint64 ignored1 : static_cast<bsl::uint64>(1);
        /// @brief defines a field in the page that must be 0
        bsl::uint64 mbz1 : static_cast<bsl::uint64>(1);
        /// @brief defines an ignored field in the page
        bsl::uint64 ignored2 : static_cast<bsl::uint64>(1);
        /// @brief defines the "available to software" field in the page
        bsl::uint64 avl : static_cast<bsl::uint64>(3);
        /// @brief defines the physical address field in the page
        bsl::uint64 phys : static_cast<bsl::uint64>(40);
        /// @brief defines fields in the page available to the OS for use
        bsl::uint64 available : static_cast<bsl::uint64>(11);
        /// @brief defines the "no-execute" field in the page
        bsl::uint64 nx : static_cast<bsl::uint64>(1);
    };

    namespace details
    {
        /// @brief defined the expected size of the pdte_t struct
        constexpr bsl::safe_uintmax EXPECTED_PDTE_T_SIZE{bsl::to_umax(8)};

        /// Check to make sure the pdte_t is the right size.
        static_assert(sizeof(pdte_t) == EXPECTED_PDTE_T_SIZE);
    }
}

#pragma pack(pop)

#endif
