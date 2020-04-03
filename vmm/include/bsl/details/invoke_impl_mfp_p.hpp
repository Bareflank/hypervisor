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

#ifndef BSL_DETAILS_INVOKE_IMPL_MFP_P_HPP
#define BSL_DETAILS_INVOKE_IMPL_MFP_P_HPP

#include "../forward.hpp"

namespace bsl
{
    namespace details
    {
        /// @class bsl::details::invoke_impl_mfp_p
        ///
        /// <!-- description -->
        ///   @brief The "invoke" function is implemented by executing the
        ///     "call" function from invoke_impl. The invoke_impl class uses
        ///     SFINAE to figure out which invoke_impl_xxx function to inherit
        ///     from. If the compiler can find a valid invoke_impl_xxx, like
        ///     possibly this class, it will inherit from it, otherwise, it
        ///     will pick the default invoke_impl implementation which is an
        ///     empty class (i.e., it does not provide a call function). This
        ///     will either result in a compiler error, or an SFINAE
        ///     substitution error, which is used to implement is_invocable,
        ///     which is why invoke is implemented using class logic instead
        ///     of a constexpr-if statement as documented by cppreference.
        ///
        class invoke_impl_mfp_p
        {
        public:
            /// <!-- description -->
            ///   @brief Invokes a member function pointer given a pointer to
            ///     an object.
            ///
            /// <!-- inputs/outputs -->
            ///   @tparam FUNC the type that defines the function being called
            ///   @tparam U the type that defines the class that encapsulates
            ///     the function being called.
            ///   @tparam T1 the type that defines the provided object. Note
            ///     that normally, U == T, but if inheritance is used, it might
            ///     not which is why U is provided instead of just using T.
            ///   @tparam TN the types that define the arguments passed to the
            ///     provided function when called.
            ///   @param f a pointer to the function being called.
            ///   @param t1 a pointer to the object for which the function is
            ///     called from.
            ///   @param tn the arguments passed to the function f when called.
            ///   @return Returns the result of calling "f" from "t1" with "tn"
            ///
            template<typename FUNC, typename U, typename T1, typename... TN>
            static constexpr auto
            call(FUNC U::*f, T1 &&t1, TN &&... tn) noexcept(
                noexcept(((*bsl::forward<T1>(t1)).*f)(bsl::forward<TN>(tn)...)))
                -> decltype(((*bsl::forward<T1>(t1)).*f)(bsl::forward<TN>(tn)...))
            {
                return ((*bsl::forward<T1>(t1)).*f)(bsl::forward<TN>(tn)...);
            }

        protected:
            /// <!-- description -->
            ///   @brief Destroyes a previously created bsl::invoke_impl_mfp_p
            ///
            ~invoke_impl_mfp_p() noexcept = default;

            /// <!-- description -->
            ///   @brief copy constructor
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being copied
            ///
            invoke_impl_mfp_p(invoke_impl_mfp_p const &o) noexcept = default;

            /// <!-- description -->
            ///   @brief move constructor
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being moved
            ///
            invoke_impl_mfp_p(invoke_impl_mfp_p &&o) noexcept = default;

            /// <!-- description -->
            ///   @brief copy assignment
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being copied
            ///   @return a reference to *this
            ///
            invoke_impl_mfp_p &operator=(invoke_impl_mfp_p const &o) &noexcept = default;

            /// <!-- description -->
            ///   @brief move assignment
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being moved
            ///   @return a reference to *this
            ///
            invoke_impl_mfp_p &operator=(invoke_impl_mfp_p &&o) &noexcept = default;
        };
    }
}

#endif
