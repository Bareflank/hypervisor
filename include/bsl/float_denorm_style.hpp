/// @copyright
/// Copyright (C) 2019 Assured Information Security, Inc.
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
///
/// @file float_denorm_style.hpp
///

#ifndef BSL_FLOATING_DENORM_STYLE_HPP
#define BSL_FLOATING_DENORM_STYLE_HPP

#include "cstdint.hpp"

namespace bsl
{
    /// @enum bsl::float_denorm_style
    ///
    /// <!-- description -->
    ///   @brief Enumerates subnormal values for floating points.
    ///
    /// <!-- notes -->
    ///   @note We do not support floating point numbers. This is only
    ///     implemented for completeness. In most cases, if you attempt
    ///     to use floating point numbers with the BSL, you will receive
    ///     a compilation error.
    ///
    enum class float_denorm_style : bsl::uint32
    {
        denorm_indeterminate = -1,
        denorm_absent = 0,
        denorm_present = 1
    };
}

#endif
