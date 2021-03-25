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

#ifndef MAP_PAGE_FLAGS_HPP
#define MAP_PAGE_FLAGS_HPP

#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>

namespace mk
{
    /// @brief Map a page with read permmissions (has no effect)
    constexpr auto MAP_PAGE_READ{0x0000000000000001_umax};
    /// @brief Map a page with write permmissions
    constexpr auto MAP_PAGE_WRITE{0x0000000000000002_umax};
    /// @brief Map a page with execute permmissions
    constexpr auto MAP_PAGE_EXECUTE{0x0000000000000004_umax};

    /// @brief Defines the auto release tag for no auto release
    constexpr auto MAP_PAGE_NO_AUTO_RELEASE{0_i32};
    /// @brief Defines the auto release tag for alloc_page allocations
    constexpr auto MAP_PAGE_AUTO_RELEASE_ALLOC_PAGE{1_i32};
    /// @brief Defines the auto release tag for alloc_huge allocations
    constexpr auto MAP_PAGE_AUTO_RELEASE_ALLOC_HUGE{2_i32};
    /// @brief Defines the auto release tag for alloc_heap allocations
    constexpr auto MAP_PAGE_AUTO_RELEASE_ALLOC_HEAP{3_i32};
    /// @brief Defines the auto release tag for stack allocations
    constexpr auto MAP_PAGE_AUTO_RELEASE_STACK{4_i32};
    /// @brief Defines the auto release tag for tls allocations
    constexpr auto MAP_PAGE_AUTO_RELEASE_TLS{5_i32};
    /// @brief Defines the auto release tag for ELF allocations
    constexpr auto MAP_PAGE_AUTO_RELEASE_ELF{6_i32};
}

#endif
