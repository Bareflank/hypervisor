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
/// @file move.hpp
///

#ifndef BSL_MOVE_HPP
#define BSL_MOVE_HPP

#include "remove_reference.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief Used to indicate that an object "val" may be "moved from",
    ///     i.e. allowing the efficient transfer of resources from "val" to
    ///     another object.
    ///   @include example_move_overview.hpp
    ///
    ///   SUPPRESSION: PRQA 4624 - false positive
    ///   - We suppress this because A7-5-1 states that a function shall not
    ///     return a pointer or reference to a parameter that is a const
    ///     reference, and this is a false positive because this is the
    ///     required definition for std::move
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type that defines the value being moved
    ///   @param val the value being moved
    ///   @return returns an xvalue expression that identifies "val"
    ///
    template<typename T>
    constexpr bsl::remove_reference_t<T> &&
    move(T &&val) noexcept
    {
        return static_cast<bsl::remove_reference_t<T> &&>(val);    // PRQA S 4624
    }
}

#endif
