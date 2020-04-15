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

#ifndef BSL_DETAILS_SWAPPABLE_TRAITS_HPP
#define BSL_DETAILS_SWAPPABLE_TRAITS_HPP

#include "../declval.hpp"
#include "../swap.hpp"
#include "../void_t.hpp"

namespace bsl
{
    namespace details
    {
        /// @brief defines the function type for swap based on the provided
        ///   arguments.
        template<typename T, typename U>
        using swappable_type = decltype(swap(declval<T>(), declval<U>()));

        /// @class bsl::details::swappable_traits
        ///
        /// <!-- description -->
        ///   @brief The swappable_traits class is used to determine if a set of
        ///     arguments are swappable and if so, how. To do this, we define
        ///     a default swappable_traits that states the provided args are not
        ///     swappable. We then define a specialized version of
        ///     swappable_traits that is only selected if a call to swap with
        ///     the provided arguments is valid. If this is true, this class
        ///     defines the states that T and U are swappable. In addition,
        ///     we use the noexcept operator to determine if T and U are
        ///     nothrow swappable. This design ensures deleting a swap function
        ///     is still supported.
        ///
        /// <!-- template parameters -->
        ///   @tparam AlwaysVoid1 is always "void"
        ///   @tparam AlwaysVoid2 is always "void"
        ///   @tparam T the first type to query
        ///   @tparam U the second type to query
        ///
        template<typename AlwaysVoid1, typename AlwaysVoid2, typename T, typename U>
        class swappable_traits
        {
        public:
            /// @brief states that the provided args are swappable
            static constexpr bool m_is_swappable_with{false};

            /// @brief states that the provided args are nothrow swappable
            static constexpr bool m_is_nothrow_swappable_with{false};

        protected:
            /// <!-- description -->
            ///   @brief Destroyes a previously created bsl::swappable_traits
            ///
            ~swappable_traits() noexcept = default;

            /// <!-- description -->
            ///   @brief copy constructor
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being copied
            ///
            constexpr swappable_traits(swappable_traits const &o) noexcept = default;

            /// <!-- description -->
            ///   @brief move constructor
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being moved
            ///
            constexpr swappable_traits(swappable_traits &&o) noexcept = default;

            /// <!-- description -->
            ///   @brief copy assignment
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being copied
            ///   @return a reference to *this
            ///
            constexpr swappable_traits &operator=(swappable_traits const &o) &noexcept = default;

            /// <!-- description -->
            ///   @brief move assignment
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being moved
            ///   @return a reference to *this
            ///
            constexpr swappable_traits &operator=(swappable_traits &&o) &noexcept = default;
        };

        /// @class bsl::details::swappable_traits
        ///
        /// <!-- description -->
        ///   @brief The swappable_traits class is used to determine if a set of
        ///     arguments are swappable and if so, how. To do this, we define
        ///     a default swappable_traits that states the provided args are not
        ///     swappable. We then define a specialized version of
        ///     swappable_traits that is only selected if a call to swap with
        ///     the provided arguments is valid. If this is true, this class
        ///     defines the states that T and U are swappable. In addition,
        ///     we use the noexcept operator to determine if T and U are
        ///     nothrow swappable. This design ensures deleting a swap function
        ///     is still supported.
        ///
        /// <!-- template parameters -->
        ///   @tparam T the first type to query
        ///   @tparam U the second type to query
        ///
        template<typename T, typename U>
        class swappable_traits<void_t<swappable_type<T, U>>, void_t<swappable_type<U, T>>, T, U>
        {
        public:
            /// @brief states that the provided args are swappable
            static constexpr bool m_is_swappable_with{true};

            /// @brief states that the provided args are nothrow swappable
            static constexpr bool m_is_nothrow_swappable_with{noexcept(
                swap(declval<T>(), declval<U>())) &&noexcept(swap(declval<U>(), declval<T>()))};

        protected:
            /// <!-- description -->
            ///   @brief Destroyes a previously created bsl::swappable_traits
            ///
            ~swappable_traits() noexcept = default;

            /// <!-- description -->
            ///   @brief copy constructor
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being copied
            ///
            constexpr swappable_traits(swappable_traits const &o) noexcept = default;

            /// <!-- description -->
            ///   @brief move constructor
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being moved
            ///
            constexpr swappable_traits(swappable_traits &&o) noexcept = default;

            /// <!-- description -->
            ///   @brief copy assignment
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being copied
            ///   @return a reference to *this
            ///
            constexpr swappable_traits &operator=(swappable_traits const &o) &noexcept = default;

            /// <!-- description -->
            ///   @brief move assignment
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being moved
            ///   @return a reference to *this
            ///
            constexpr swappable_traits &operator=(swappable_traits &&o) &noexcept = default;
        };
    }
}

#endif
