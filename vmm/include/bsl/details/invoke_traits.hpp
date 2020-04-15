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

#ifndef BSL_DETAILS_INVOKE_TRAITS_HPP
#define BSL_DETAILS_INVOKE_TRAITS_HPP

#include "../declval.hpp"
#include "../is_convertible.hpp"
#include "../is_nothrow_convertible.hpp"
#include "../is_void.hpp"
#include "../invoke.hpp"
#include "../void_t.hpp"

namespace bsl
{
    namespace details
    {
        /// @brief defines the function type for invoke based on the provided
        ///   arguments.
        template<typename FUNC, typename... TN>
        using invoke_type = decltype(invoke(declval<FUNC>(), declval<TN>()...));

        /// @class bsl::details::invoke_traits
        ///
        /// <!-- description -->
        ///   @brief The invoke_traits class is used to determine if a set of
        ///     arguments are invocable and if so, how. To do this, we define
        ///     a default invoke_traits that states the provided args are not
        ///     callable. We then define a specialized version of invoke_traits
        ///     that is only selected if a call to invoke with the provided
        ///     arguments is valid. If this is true, this class defines the
        ///     "type" alias which is used by invoke_result, as well as 4
        ///     bools that define the different ways in which the args are
        ///     callable (based on the APIs that C++ supports) which are all
        ///     used by is_vocable and friends. The reason we define the
        ///     "type" alias is that the invoke_result should be capable of
        ///     acting as is_invocable as well, meaning invoke_result only
        ///     defines the "type" alias when the arguments define a callable.
        ///     If a callable cannot be formed, this alias is not provided,
        ///     allowing invoke_result to be used in SFINAE.
        ///
        /// <!-- template parameters -->
        ///   @tparam AlwaysVoid is always "void"
        ///   @tparam FUNC the type that defines the function being called
        ///   @tparam TN the types that define the arguments passed to the
        ///     provided function when called.
        ///
        template<typename AlwaysVoid, typename FUNC, typename... TN>
        class invoke_traits
        {
        public:
            /// @brief states that the provided args do not form a callable
            static constexpr bool m_is_invocable{false};

            /// @brief states that the provided args do not form a callable
            static constexpr bool m_is_nothrow_invocable{false};

            /// @brief states that the provided args do not form a callable
            template<typename R>
            static constexpr bool m_is_invocable_r{false};

            /// @brief states that the provided args do not form a callable
            template<typename R>
            static constexpr bool m_is_nothrow_invocable_r{false};

        protected:
            /// <!-- description -->
            ///   @brief Destroyes a previously created bsl::invoke_traits
            ///
            ~invoke_traits() noexcept = default;

            /// <!-- description -->
            ///   @brief copy constructor
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being copied
            ///
            constexpr invoke_traits(invoke_traits const &o) noexcept = default;

            /// <!-- description -->
            ///   @brief move constructor
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being moved
            ///
            constexpr invoke_traits(invoke_traits &&o) noexcept = default;

            /// <!-- description -->
            ///   @brief copy assignment
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being copied
            ///   @return a reference to *this
            ///
            constexpr invoke_traits &operator=(invoke_traits const &o) &noexcept = default;

            /// <!-- description -->
            ///   @brief move assignment
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being moved
            ///   @return a reference to *this
            ///
            constexpr invoke_traits &operator=(invoke_traits &&o) &noexcept = default;
        };

        /// @class bsl::details::invoke_traits
        ///
        /// <!-- description -->
        ///   @brief The invoke_traits class is used to determine if a set of
        ///     arguments are invocable and if so, how. To do this, we define
        ///     a default invoke_traits that states the provided args are not
        ///     callable. We then define a specialized version of invoke_traits
        ///     that is only selected if a call to invoke with the provided
        ///     arguments is valid. If this is true, this class defines the
        ///     "type" alias which is used by invoke_result, as well as 4
        ///     bools that define the different ways in which the args are
        ///     callable (based on the APIs that C++ supports) which are all
        ///     used by is_vocable and friends. The reason we define the
        ///     "type" alias is that the invoke_result should be capable of
        ///     acting as is_invocable as well, meaning invoke_result only
        ///     defines the "type" alias when the arguments define a callable.
        ///     If a callable cannot be formed, this alias is not provided,
        ///     allowing invoke_result to be used in SFINAE.
        ///
        /// <!-- template parameters -->
        ///   @tparam FUNC the type that defines the function being called
        ///   @tparam TN the types that define the arguments passed to the
        ///     provided function when called.
        ///
        template<typename FUNC, typename... TN>
        class invoke_traits<void_t<invoke_type<FUNC, TN...>>, FUNC, TN...>
        {
        public:
            /// @brief provides the member typedef "type"
            using type = invoke_type<FUNC, TN...>;

            /// @brief states that the provided args form a callable
            static constexpr bool m_is_invocable{true};

            /// @brief states whether or not the provided args form a nothrow
            ///   callable
            static constexpr bool m_is_nothrow_invocable{
                noexcept(invoke(declval<FUNC>(), declval<TN>()...))};

            /// @brief states whether or not the provided args form a callable
            ///   that is convertible to R
            template<typename R>
            static constexpr bool m_is_invocable_r{
                (is_void<R>::value || is_convertible<R, type>::value)};

            /// @brief states whether or not the provided args form a nothrow
            ///   callable that is convertible to R
            template<typename R>
            static constexpr bool m_is_nothrow_invocable_r{
                noexcept(invoke(declval<FUNC>(), declval<TN>()...)) &&
                (is_void<R>::value || is_nothrow_convertible<R, type>::value)};

        protected:
            /// <!-- description -->
            ///   @brief Destroyes a previously created bsl::invoke_traits
            ///
            ~invoke_traits() noexcept = default;

            /// <!-- description -->
            ///   @brief copy constructor
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being copied
            ///
            constexpr invoke_traits(invoke_traits const &o) noexcept = default;

            /// <!-- description -->
            ///   @brief move constructor
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being moved
            ///
            constexpr invoke_traits(invoke_traits &&o) noexcept = default;

            /// <!-- description -->
            ///   @brief copy assignment
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being copied
            ///   @return a reference to *this
            ///
            constexpr invoke_traits &operator=(invoke_traits const &o) &noexcept = default;

            /// <!-- description -->
            ///   @brief move assignment
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being moved
            ///   @return a reference to *this
            ///
            constexpr invoke_traits &operator=(invoke_traits &&o) &noexcept = default;
        };
    }
}

#endif
