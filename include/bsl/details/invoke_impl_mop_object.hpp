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

#ifndef BSL_DETAILS_INVOKE_IMPL_MOP_OBJECT_HPP
#define BSL_DETAILS_INVOKE_IMPL_MOP_OBJECT_HPP

#include "../forward.hpp"

namespace bsl
{
    namespace details
    {
        /// @class bsl::details::invoke_impl_mop_object
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
        class invoke_impl_mop_object
        {
        public:
            /// <!-- description -->
            ///   @brief Invokes a member object pointer given a reference to
            ///     an object.
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            /// <!-- inputs/outputs -->
            ///   @tparam FUNC the type that defines the function being called
            ///   @tparam U the type that defines the class that encapsulates
            ///     the function being called.
            ///   @tparam T1 the type that defines the provided object. Note
            ///     that normally, U == T, but if inheritance is used, it might
            ///     not which is why U is provided instead of just using T.
            ///   @param f a pointer to the function being called.
            ///   @param t1 a reference to the object for which the function is
            ///     called from.
            ///   @return Returns the result of calling "f" from "t1" with "tn"
            ///
            template<typename FUNC, typename U, typename T1>
            static constexpr auto
            call(FUNC U::*f, T1 &&t1) noexcept(noexcept(bsl::forward<T1>(t1).*f))
                -> decltype(bsl::forward<T1>(t1).*f)
            {
                return bsl::forward<T1>(t1).*f;
            }

        protected:
            /// <!-- description -->
            ///   @brief copy constructor
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being copied
            ///
            constexpr invoke_impl_mop_object(invoke_impl_mop_object const &o) noexcept = default;

            /// <!-- description -->
            ///   @brief move constructor
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being moved
            ///
            constexpr invoke_impl_mop_object(invoke_impl_mop_object &&o) noexcept = default;

            /// <!-- description -->
            ///   @brief copy assignment
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being copied
            ///   @return a reference to *this
            ///
            [[maybe_unused]] constexpr invoke_impl_mop_object &    // --
            operator=(invoke_impl_mop_object const &o) &noexcept = default;

            /// <!-- description -->
            ///   @brief move assignment
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being moved
            ///   @return a reference to *this
            ///
            [[maybe_unused]] constexpr invoke_impl_mop_object &    // --
            operator=(invoke_impl_mop_object &&o) &noexcept = default;

            /// <!-- description -->
            ///   @brief Destroyes a previously created bsl::invoke_impl_mop_object
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            ~invoke_impl_mop_object() noexcept = default;
        };
    }
}

#endif
