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

#ifndef BSL_DETAILS_INVOKE_IMPL_HPP
#define BSL_DETAILS_INVOKE_IMPL_HPP

#include "invoke_impl_base.hpp"

namespace bsl
{
    namespace details
    {
        /// @class bsl::details::invoke_impl
        ///
        /// <!-- description -->
        ///   @brief The "invoke" function is implemented by executing the
        ///     "call" function from invoke_impl. The invoke_impl class uses
        ///     SFINAE to figure out which invoke_impl_xxx function to inherit
        ///     from. If the compiler can find a valid invoke_impl_xxx, it will
        ///     inherit from it, otherwise, it will pick the default invoke_impl
        ///     implementation which is an empty class (i.e., it does not
        ///     provide a call function). This will either result in a compiler
        ///     error, or an SFINAE substitution error, which is used to
        ///     implement is_invocable, which is why invoke is implemented
        ///     using class logic instead of a constexpr-if statement as
        ///     documented by cppreference.
        ///
        template<typename FUNC, typename... TN>
        class invoke_impl final : public invoke_impl_base<FUNC, void>
        {};

        /// @class bsl::details::invoke_impl
        ///
        /// <!-- description -->
        ///   @brief The "invoke" function is implemented by executing the
        ///     "call" function from invoke_impl. The invoke_impl class uses
        ///     SFINAE to figure out which invoke_impl_xxx function to inherit
        ///     from. If the compiler can find a valid invoke_impl_xxx, it will
        ///     inherit from it, otherwise, it will pick the default invoke_impl
        ///     implementation which is an empty class (i.e., it does not
        ///     provide a call function). This will either result in a compiler
        ///     error, or an SFINAE substitution error, which is used to
        ///     implement is_invocable, which is why invoke is implemented
        ///     using class logic instead of a constexpr-if statement as
        ///     documented by cppreference.
        ///
        template<typename FUNC, typename T1, typename... TN>
        class invoke_impl<FUNC, T1, TN...> final : public invoke_impl_base<FUNC, T1>
        {};
    }
}

#endif
