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
/// @file is_swappable.hpp
///

#ifndef BSL_IS_SWAPPABLE_HPP
#define BSL_IS_SWAPPABLE_HPP

#include "bool_constant.hpp"
#include "add_lvalue_reference.hpp"
#include "is_swappable_with.hpp"

namespace bsl
{
    /// @class bsl::is_swappable
    ///
    /// <!-- description -->
    ///   @brief If the provided type T is swappable, provides
    ///     the member constant value equal to true. Otherwise the member
    ///     constant value is false.
    ///   @include example_is_swappable_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the first type to query
    ///
    template<typename T>
    class is_swappable final :
        public bool_constant<
            is_swappable_with<add_lvalue_reference_t<T>, add_lvalue_reference_t<T>>::value>
    {};
}

#endif
