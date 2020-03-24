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
/// @file extent.hpp
///

#ifndef BSL_EXTENT_HPP
#define BSL_EXTENT_HPP

#include "details/extent_base.hpp"

namespace bsl
{
    /// @class bsl::extent
    ///
    /// <!-- description -->
    ///   @brief If T is an array type, provides the member constant value
    ///     equal to the number of elements along the Nth dimension of the
    ///     array, if N is in [0, std::rank<T>::value). For any other type, or
    ///     if T is an array of unknown bound along its first dimension and N
    ///     is 0, value is 0.
    ///   @include example_extent_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type to get the extent from
    ///   @tparam N the dimension of T to the the extent from
    ///
    template<typename T, bsl::uintmax N = 0>
    class extent final : public details::extent_base<T, N>
    {};
}

#endif
