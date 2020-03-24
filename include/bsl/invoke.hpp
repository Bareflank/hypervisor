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
/// @file invoke.hpp
///

#ifndef BSL_INVOKE_HPP
#define BSL_INVOKE_HPP

#include "details/invoke_impl.hpp"
#include "forward.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief Invokes the callable object "f" with arguments "tn".
    ///
    /// <!-- contracts -->
    ///   @pre expects func != nullptr. Note that this pre-condition is
    ///     not validated as there is no way to report an error. We do
    ///     provide safe_invoke() versions of invoke() that resolve this
    ///     issue and should be used instead. invoke() is only provided
    ///     to ensure support with 3rd party libraries.
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam FUNC the type that defines the function being called
    ///   @tparam TN the types that define the arguments passed to the
    ///     provided function when called.
    ///   @param f a pointer to the function being called.
    ///   @param tn the arguments passed to the function f when called.
    ///   @return Returns the result of calling "f" with "tn"
    ///
    template<typename FUNC, typename... TN>
    constexpr auto
    invoke(FUNC &&f, TN &&... tn) noexcept(                     // --
        noexcept(details::invoke_impl<FUNC, TN...>::call(       // --
            bsl::forward<FUNC>(f),                              // --
            bsl::forward<TN>(tn)...)))                          // --
        -> decltype(details::invoke_impl<FUNC, TN...>::call(    // --
            bsl::forward<FUNC>(f),                              // --
            bsl::forward<TN>(tn)...))                           // --
    {                                                           // --
        return details::invoke_impl<FUNC, TN...>::call(         // --
            bsl::forward<FUNC>(f),                              // --
            bsl::forward<TN>(tn)...);                           // --
    }
}

#endif
