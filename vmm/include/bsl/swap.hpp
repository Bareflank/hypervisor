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
///
/// @file swap.hpp
///

#ifndef BSL_SWAP_HPP
#define BSL_SWAP_HPP

#include "cstdint.hpp"
#include "move.hpp"
#include "enable_if.hpp"
#include "is_movable.hpp"
#include "is_nothrow_movable.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief Swaps the given values.
    ///   @include example_swap_overview.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type that defines the values being swapped
    ///   @param lhs the value being swapped with rhs
    ///   @param rhs the value being swapped with lhs
    ///   @return return's void
    ///
    /// <!-- inputs/outputs -->
    ///   @throw throws if move construction or assignment of T throws
    ///
    template<typename T>
    constexpr enable_if_t<is_movable<T>::value>
    swap(T &lhs, T &rhs) noexcept(is_nothrow_movable<T>::value)
    {
        T tmp{bsl::move(lhs)};
        lhs = bsl::move(rhs);
        rhs = bsl::move(tmp);
    }
}

#endif
