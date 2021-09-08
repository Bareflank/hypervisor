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

#ifndef BASIC_PAGE_4K_T_HPP
#define BASIC_PAGE_4K_T_HPP

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>

namespace lib
{
    /// @brief defines total number of bytes in a 4k page
    constexpr auto BASIC_PAGE_4K_T_SIZE{0x1000_umx};
    /// @brief defines the page shift for a 4k page
    constexpr auto BASIC_PAGE_4K_T_SHFT{12_u64};
    /// @brief defines the page mask for a 4k page
    constexpr auto BASIC_PAGE_4K_T_MASK{
        bsl::to_u64(BASIC_PAGE_4K_T_SIZE) - bsl::safe_u64::magic_1()};

    /// @struct lib::basic_page_4k_t
    ///
    /// <!-- description -->
    ///   @brief Defines a 4k page
    ///
    struct basic_page_4k_t final
    {
        /// @brief stores the data in the page
        bsl::array<bsl::uint8, BASIC_PAGE_4K_T_SIZE.get()> data;
    };

    /// @brief sanity check
    static_assert(sizeof(basic_page_4k_t) == BASIC_PAGE_4K_T_SIZE);
}

#endif
