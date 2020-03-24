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
/// @file min.hpp
///

#ifndef BSL_MIN_HPP
#define BSL_MIN_HPP

#include "forward.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief Returns a if a is smaller than b, otherwise returns b.
    ///   @include example_min_overview.hpp
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T The type that defines both a and b
    ///   @param a the first parameter to compare
    ///   @param b the second parameter to compare
    ///   @return Returns a if a is smaller than b, otherwise returns b.
    ///
    template<typename T>
    constexpr T const &
    min(T const &a, T const &b)
    {
        return (b < a) ? b : a;
    }

    /// <!-- description -->
    ///   @brief Returns a if a is smaller than b, otherwise returns b. Uses
    ///     Comapre to perform the comparison instead of <
    ///   @include example_min_overview.hpp
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T The type that defines both a and b
    ///   @tparam COMPARE The type that defines the compare function
    ///   @param a the first parameter to compare
    ///   @param b the second parameter to compare
    ///   @param comp A function that returns true if b is less than a.
    ///   @return Returns a if a is smaller than b, otherwise returns b.
    ///
    template<typename T, typename COMPARE>
    constexpr T const &
    min(T const &a, T const &b, COMPARE &&comp)
    {
        return (bsl::forward<COMPARE>(comp)(a, b)) ? b : a;
    }
}

#endif
