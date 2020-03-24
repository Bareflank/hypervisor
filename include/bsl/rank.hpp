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
/// @file rank.hpp
///

#ifndef BSL_RANK_HPP
#define BSL_RANK_HPP

#include "cstdint.hpp"
#include "integral_constant.hpp"

namespace bsl
{
    /// @class bsl::rank
    ///
    /// <!-- description -->
    ///   @brief If T is an array type, provides the member constant value
    ///     equal to the number of dimensions of the array.
    ///     For any other type, value is 0.
    ///   @include example_rank_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type to get the rank from
    ///
    template<typename T>
    class rank final :    // --
        public integral_constant<bsl::uintmax, 0>
    {};

    /// @cond doxygen off

    template<typename T>
    class rank<T[]> final :    // NOLINT
        public integral_constant<bsl::uintmax, rank<T>::value + 1>
    {};

    template<typename T, bsl::uintmax N>
    class rank<T[N]> final :    // NOLINT
        public integral_constant<bsl::uintmax, rank<T>::value + 1>
    {};

    /// @endcond doxygen on
}

#endif
