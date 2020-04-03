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

#ifndef BSL_DETAILS_INVOKE_IMPL_BASE_HPP
#define BSL_DETAILS_INVOKE_IMPL_BASE_HPP

#include "invoke_impl_fp.hpp"
#include "invoke_impl_mfp_o.hpp"
#include "invoke_impl_mfp_p.hpp"
#include "invoke_impl_mfp_r.hpp"
#include "invoke_impl_mop_o.hpp"
#include "invoke_impl_mop_p.hpp"
#include "invoke_impl_mop_r.hpp"

#include "../decay.hpp"
#include "../conditional.hpp"
#include "../forward.hpp"
#include "../is_base_of.hpp"
#include "../is_member_function_pointer.hpp"
#include "../is_member_object_pointer.hpp"
#include "../is_reference_wrapper.hpp"
#include "../remove_cvref.hpp"

namespace bsl
{
    namespace details
    {
        /// @class bsl::details::invoke_impl_base
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
        template<
            typename FUNC,
            typename T1,
            bool is_mfp = is_member_function_pointer<remove_cvref_t<FUNC>>::value,
            bool is_mop = is_member_object_pointer<remove_cvref_t<FUNC>>::value>
        class invoke_impl_base
        {
        protected:
            /// <!-- description -->
            ///   @brief Destroyes a previously created bsl::invoke_impl_base
            ///
            ~invoke_impl_base() noexcept = default;

            /// <!-- description -->
            ///   @brief copy constructor
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being copied
            ///
            invoke_impl_base(invoke_impl_base const &o) noexcept = default;

            /// <!-- description -->
            ///   @brief move constructor
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being moved
            ///
            invoke_impl_base(invoke_impl_base &&o) noexcept = default;

            /// <!-- description -->
            ///   @brief copy assignment
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being copied
            ///   @return a reference to *this
            ///
            invoke_impl_base &operator=(invoke_impl_base const &o) &noexcept = default;

            /// <!-- description -->
            ///   @brief move assignment
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being moved
            ///   @return a reference to *this
            ///
            invoke_impl_base &operator=(invoke_impl_base &&o) &noexcept = default;
        };

        /// @class bsl::details::invoke_impl_base
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
        template<typename FUNC, typename U, typename T1>
        class invoke_impl_base<FUNC U::*, T1, true, false> :
            public conditional_t<
                is_base_of<U, decay_t<T1>>::value,
                invoke_impl_mfp_o,
                conditional_t<
                    is_reference_wrapper<decay_t<T1>>::value,
                    invoke_impl_mfp_r,
                    invoke_impl_mfp_p>>
        {
        protected:
            /// <!-- description -->
            ///   @brief Destroyes a previously created bsl::invoke_impl_base
            ///
            ~invoke_impl_base() noexcept = default;

            /// <!-- description -->
            ///   @brief copy constructor
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being copied
            ///
            invoke_impl_base(invoke_impl_base const &o) noexcept = default;

            /// <!-- description -->
            ///   @brief move constructor
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being moved
            ///
            invoke_impl_base(invoke_impl_base &&o) noexcept = default;

            /// <!-- description -->
            ///   @brief copy assignment
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being copied
            ///   @return a reference to *this
            ///
            invoke_impl_base &operator=(invoke_impl_base const &o) &noexcept = default;

            /// <!-- description -->
            ///   @brief move assignment
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being moved
            ///   @return a reference to *this
            ///
            invoke_impl_base &operator=(invoke_impl_base &&o) &noexcept = default;
        };

        /// @class bsl::details::invoke_impl_base
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
        template<typename FUNC, typename U, typename T1>
        class invoke_impl_base<FUNC U::*, T1, false, true> :
            public conditional_t<
                is_base_of<U, decay_t<T1>>::value,
                invoke_impl_mop_o,
                conditional_t<
                    is_reference_wrapper<decay_t<T1>>::value,
                    invoke_impl_mop_r,
                    invoke_impl_mop_p>>
        {
        protected:
            /// <!-- description -->
            ///   @brief Destroyes a previously created bsl::invoke_impl_base
            ///
            ~invoke_impl_base() noexcept = default;

            /// <!-- description -->
            ///   @brief copy constructor
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being copied
            ///
            invoke_impl_base(invoke_impl_base const &o) noexcept = default;

            /// <!-- description -->
            ///   @brief move constructor
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being moved
            ///
            invoke_impl_base(invoke_impl_base &&o) noexcept = default;

            /// <!-- description -->
            ///   @brief copy assignment
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being copied
            ///   @return a reference to *this
            ///
            invoke_impl_base &operator=(invoke_impl_base const &o) &noexcept = default;

            /// <!-- description -->
            ///   @brief move assignment
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being moved
            ///   @return a reference to *this
            ///
            invoke_impl_base &operator=(invoke_impl_base &&o) &noexcept = default;
        };

        /// @class bsl::details::invoke_impl_base
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
        template<typename FUNC, typename T1>
        class invoke_impl_base<FUNC, T1, false, false> : public invoke_impl_fp
        {
        protected:
            /// <!-- description -->
            ///   @brief Destroyes a previously created bsl::invoke_impl_base
            ///
            ~invoke_impl_base() noexcept = default;

            /// <!-- description -->
            ///   @brief copy constructor
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being copied
            ///
            invoke_impl_base(invoke_impl_base const &o) noexcept = default;

            /// <!-- description -->
            ///   @brief move constructor
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being moved
            ///
            invoke_impl_base(invoke_impl_base &&o) noexcept = default;

            /// <!-- description -->
            ///   @brief copy assignment
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being copied
            ///   @return a reference to *this
            ///
            invoke_impl_base &operator=(invoke_impl_base const &o) &noexcept = default;

            /// <!-- description -->
            ///   @brief move assignment
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being moved
            ///   @return a reference to *this
            ///
            invoke_impl_base &operator=(invoke_impl_base &&o) &noexcept = default;
        };
    }
}

#endif
