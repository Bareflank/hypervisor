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

#ifndef MEMORY_TYPE_HPP
#define MEMORY_TYPE_HPP

#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>

namespace example
{
    /// @brief defines the uncacheable memory type
    constexpr bsl::safe_uintmax MEMORY_TYPE_UC{bsl::to_umax(0)};
    /// @brief defines the write-combine memory type
    constexpr bsl::safe_uintmax MEMORY_TYPE_WC{bsl::to_umax(1)};
    /// @brief defines the write-through memory type
    constexpr bsl::safe_uintmax MEMORY_TYPE_WT{bsl::to_umax(4)};
    /// @brief defines the write-protect memory type
    constexpr bsl::safe_uintmax MEMORY_TYPE_WP{bsl::to_umax(5)};
    /// @brief defines the write-back memory type
    constexpr bsl::safe_uintmax MEMORY_TYPE_WB{bsl::to_umax(6)};
}

#endif
