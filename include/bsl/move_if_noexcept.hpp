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
/// @file move_if_noexcept.hpp
///

#ifndef BSL_MOVE_IF_NOEXCEPT_HPP
#define BSL_MOVE_IF_NOEXCEPT_HPP

#include "conditional.hpp"
#include "is_copy_constructible.hpp"
#include "is_nothrow_move_constructible.hpp"
#include "move.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief move_if_noexcept obtains an rvalue reference to its argument
    ///     if its move constructor does not throw exceptions or if there is
    ///     no copy constructor (move-only type), otherwise obtains an lvalue
    ///     reference to its argument. It is typically used to combine move
    ///     semantics with strong exception guarantee.
    ///   @include example_move_if_noexcept_overview.hpp
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type that defines the value being moved
    ///   @param val the value being moved
    ///   @return std::move(val) or val, depending on exception guarantees.
    ///
    template<typename T>
    constexpr conditional_t<
        !is_nothrow_move_constructible<T>::value && is_copy_constructible<T>::value,
        const T &,
        T &&>
    move_if_noexcept(T &val) noexcept
    {
        return move(val);
    }

}

#endif
