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
/// @file as_const.hpp
///

#ifndef BSL_AS_CONST_HPP
#define BSL_AS_CONST_HPP

#include "add_const.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief Forms lvalue reference to const type of t
    ///   @include example_as_const_overview.hpp
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type to form the lvalue reference to const of
    ///   @param t the object of type T to form the const lvalue reference of
    ///   @return Forms lvalue reference to const type of t
    ///
    template<typename T>
    constexpr add_const_t<T> &
    as_const(T &t) noexcept
    {
        return t;
    }

    /// <!-- description -->
    ///   @brief const rvalue reference overload is deleted to disallow rvalue
    ///     arguments
    ///   @include example_as_const_overview.hpp
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type to form the lvalue reference to const of
    ///   @param t the object of type T to form the const lvalue reference of
    ///
    template<typename T>
    constexpr void as_const(T const &&t) noexcept = delete;
}

#endif
