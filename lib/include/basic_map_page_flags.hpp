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

#ifndef BASIC_MAP_PAGE_FLAGS_HPP
#define BASIC_MAP_PAGE_FLAGS_HPP

#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>

namespace lib
{
    /// @brief map a page with read permmissions
    constexpr auto BASIC_MAP_PAGE_READ{0x0000000000000001_umx};
    /// @brief map a page with write permmissions
    constexpr auto BASIC_MAP_PAGE_WRITE{0x0000000000000002_umx};
    /// @brief map a page with execute permmissions
    constexpr auto BASIC_MAP_PAGE_EXECUTE{0x0000000000000004_umx};
    /// @brief map a page with read/write permmissions
    constexpr auto BASIC_MAP_PAGE_RW{BASIC_MAP_PAGE_READ | BASIC_MAP_PAGE_WRITE};
    /// @brief map a page with read/execute permmissions
    constexpr auto BASIC_MAP_PAGE_RE{BASIC_MAP_PAGE_READ | BASIC_MAP_PAGE_EXECUTE};
}

#endif
