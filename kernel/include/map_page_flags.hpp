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

#include <basic_map_page_flags.hpp>

namespace mk
{
    /// @brief map a page with read permmissions
    constexpr auto MAP_PAGE_READ{lib::BASIC_MAP_PAGE_READ};
    /// @brief map a page with write permmissions
    constexpr auto MAP_PAGE_WRITE{lib::BASIC_MAP_PAGE_WRITE};
    /// @brief map a page with execute permmissions
    constexpr auto MAP_PAGE_EXECUTE{lib::BASIC_MAP_PAGE_EXECUTE};
    /// @brief map a page with read/write permmissions
    constexpr auto MAP_PAGE_RW{lib::BASIC_MAP_PAGE_RW};
    /// @brief map a page with read/execute permmissions
    constexpr auto MAP_PAGE_RE{lib::BASIC_MAP_PAGE_RE};
}

#endif
