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

#ifndef EXAMPLE_FORWARD_OVERVIEW_HPP
#define EXAMPLE_FORWARD_OVERVIEW_HPP

#include <bsl/forward.hpp>
#include <bsl/discard.hpp>
#include <bsl/is_lvalue_reference.hpp>
#include <bsl/move.hpp>
#include <bsl/print.hpp>

namespace bsl
{
    /// <!-- description -->
    ///   @brief If this function is given an lvalue reference, it returns
    ///     true. Otherwise this function will return false.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T The type being queired
    ///   @param t the value of the type being provided
    ///   @return If this function is given an lvalue reference, it returns
    ///     true. Otherwise this function will return false.
    ///
    template<typename T>
    constexpr bool
    detector(T &&t) noexcept
    {
        bsl::discard(t);
        return bsl::is_lvalue_reference<decltype(t)>::value;
    }

    /// <!-- description -->
    ///   @brief Forwards the provided argument to the detector using
    ///     bsl::forward, which will preserve the lvalue/rvalueness of the
    ///     provided argument.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T The type being queired
    ///   @param t the value of the type being provided
    ///   @return If this function is given an lvalue reference, it returns
    ///     true. Otherwise this function will return false.
    ///
    template<typename T>
    constexpr bool
    forwarder(T &&t) noexcept
    {
        return detector(bsl::forward<T>(t));
    }

    /// <!-- description -->
    ///   @brief Provides the example's main function
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    inline void
    example_forward_overview() noexcept
    {
        bsl::int32 const val1{42};
        bsl::int32 val2{val1};

        if (forwarder(val1)) {
            bsl::print("success\n");
        }

        if (!forwarder(bsl::move(val2))) {
            bsl::print("success\n");
        }
    }
}

#endif
