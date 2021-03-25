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

namespace example
{
    /// @brief Map a page with read permmissions (has no effect)
    constexpr bsl::safe_uintmax MAP_PAGE_READ{bsl::to_umax(0x0000000000000001U)};
    /// @brief Map a page with write permmissions
    constexpr bsl::safe_uintmax MAP_PAGE_WRITE{bsl::to_umax(0x0000000000000002U)};
    /// @brief Map a page with execute permmissions
    constexpr bsl::safe_uintmax MAP_PAGE_EXECUTE{bsl::to_umax(0x0000000000000004U)};

    /// @brief Map a page with read/execute permmissions
    constexpr bsl::safe_uintmax MAP_PAGE_RE{MAP_PAGE_READ | MAP_PAGE_EXECUTE};
    /// @brief Map a page with read/write permmissions
    constexpr bsl::safe_uintmax MAP_PAGE_RW{MAP_PAGE_READ | MAP_PAGE_WRITE};
    /// @brief Map a page with read/write/execute permmissions
    constexpr bsl::safe_uintmax MAP_PAGE_RWE{MAP_PAGE_READ | MAP_PAGE_WRITE | MAP_PAGE_EXECUTE};
}

#endif
