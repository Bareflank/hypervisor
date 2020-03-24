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
/// @file is_constant_evaluated.hpp
///

#ifndef BSL_IS_CONSTANT_EVALUATED_HPP
#define BSL_IS_CONSTANT_EVALUATED_HPP

namespace bsl
{
    /// <!-- description -->
    ///   @brief Detects whether the function call occurs within a
    ///     constant-evaluated context. Returns true if the evaluation of the
    ///     call occurs within the evaluation of an expression or conversion
    ///     that is manifestly constant-evaluated; otherwise returns false.
    ///   @include example_is_constant_evaluated_overview.hpp
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the evaluation of the
    ///     call occurs within the evaluation of an expression or conversion
    ///     that is manifestly constant-evaluated; otherwise returns false.
    ///
    [[nodiscard]] constexpr bool
    is_constant_evaluated() noexcept
    {
        return __builtin_is_constant_evaluated();
    }
}

#endif
