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
/// @file swap.hpp
///

#ifndef BSL_SWAP_HPP
#define BSL_SWAP_HPP

#include "cstdint.hpp"
#include "discard.hpp"
#include "for_each.hpp"
#include "move.hpp"
#include "enable_if.hpp"
#include "is_move_assignable.hpp"
#include "is_move_constructible.hpp"
#include "is_nothrow_move_assignable.hpp"
#include "is_nothrow_move_constructible.hpp"

// clang-format off

namespace bsl
{
    /// <!-- description -->
    ///   @brief Swaps the given values.
    ///   @include example_swap_overview.hpp
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type that defines the values being swapped
    ///   @param lhs the value being swapped with rhs
    ///   @param rhs the value being swapped with lhs
    ///
    template<
        typename T,
        enable_if_t<is_move_assignable<T>::value> = true,
        enable_if_t<is_move_constructible<T>::value> = true>
    constexpr void
    swap(T &lhs, T &rhs) noexcept(
        is_nothrow_move_constructible<T>::value &&
        is_nothrow_move_assignable<T>::value)
    {
        T tmp{bsl::move(lhs)};
        lhs = bsl::move(rhs);
        rhs = bsl::move(tmp);
    }

    /// <!-- description -->
    ///   @brief Swaps the elements in two arrays
    ///   @include example_swap_overview.hpp
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type that defines the arrays being swapped
    ///   @tparam N the size of the arrays
    ///   @param lhs the value being swapped with rhs
    ///   @param rhs the value being swapped with lhs
    ///
    template<
        typename T,
        bsl::uintmax N,
        enable_if_t<is_move_assignable<T>::value> = true,
        enable_if_t<is_move_constructible<T>::value> = true>
    constexpr void
    swap(T (&lhs)[N], T (&rhs)[N]) noexcept(    // NOLINT
        is_nothrow_move_constructible<T>::value &&
        is_nothrow_move_assignable<T>::value)
    {
        for_each(lhs, [&rhs](auto &elem, auto i) noexcept(swap(elem, rhs[i])) {    // NOLINT
            swap(elem, rhs[i]);
        });
    }
}

// clang-format on

#endif
