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
/// @file is_nothrow_convertible.hpp
///

#ifndef BSL_IS_NOTHROW_CONVERTIBLE_HPP
#define BSL_IS_NOTHROW_CONVERTIBLE_HPP

#include "bool_constant.hpp"
#include "declval.hpp"
#include "false_type.hpp"
#include "is_void.hpp"
#include "true_type.hpp"

namespace bsl
{
    namespace details
    {
        /// <!-- description -->
        ///   @brief Tests if the provided type is returnable, which is
        ///     required for a type to be convertible. If the type is
        ///     returnable, this returns true, false otherwise.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T The type to query
        ///   @param ignored (only used for overload resolution)
        ///   @return returns true if T is returnable, false otherwise
        ///
        template<typename T>
        auto test_is_nothrow_convertible1(bsl::int32 ignored) noexcept -> true_type_for<T()>;

        /// <!-- description -->
        ///   @brief Tests if the provided type is returnable, which is
        ///     required for a type to be convertible. If the type is
        ///     returnable, this returns true, false otherwise.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T The type to query
        ///   @param ignored (only used for overload resolution)
        ///   @return returns true if T is returnable, false otherwise
        ///
        template<typename T>
        auto test_is_nothrow_convertible1(bool ignored) noexcept -> false_type;

        /// <!-- description -->
        ///   @brief Tests whether or not the provided to can be converted from
        ///     "From" to "To" via a function parameter similar to an implicit
        ///     conversion constructor (but might be implicitly provided
        ///     by the compiler). If the type is convertible, this returns
        ///     true, false otherwise.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam From the type to convert to
        ///   @tparam To the type to convert from
        ///   @param ignored (only used for overload resolution)
        ///   @return returns true if T is returnable, false otherwise
        ///
        template<typename From, typename To>
        auto test_is_nothrow_convertible2(bsl::int32 ignored) noexcept -> bool_constant<
            noexcept(declval<void (&)(To) noexcept>()(declval<From>()))>;    // NOLINT

        /// <!-- description -->
        ///   @brief Tests whether or not the provided to can be converted from
        ///     "From" to "To" via a function parameter similar to an implicit
        ///     conversion constructor (but might be implicitly provided
        ///     by the compiler). If the type is convertible, this returns
        ///     true, false otherwise.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam From the type to convert to
        ///   @tparam To the type to convert from
        ///   @param ignored (only used for overload resolution)
        ///   @return returns true if T is returnable, false otherwise
        ///
        template<typename From, typename To>
        auto test_is_nothrow_convertible2(bool ignored) noexcept -> false_type;

        /// <!-- description -->
        ///   @brief Performs all of the tests including testing if both
        ///     types are void
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam From the type to convert to
        ///   @tparam To the type to convert from
        ///   @return returns true if T is returnable, false otherwise
        ///
        template<typename From, typename To>
        [[nodiscard]] constexpr bool
        check_is_nothrow_convertible() noexcept
        {
            if constexpr (is_void<From>::value && is_void<To>::value) {
                return true;
            }

            return decltype(test_is_nothrow_convertible2<From, To>(0))::value &&
                   decltype(test_is_nothrow_convertible1<To>(0))::value;
        }
    }

    /// @class bsl::is_nothrow_convertible
    ///
    /// <!-- description -->
    ///   @brief If the provided type is convertible from "From" to "To",
    ///     provides the member constant value equal to true. Otherwise the
    ///     member constant value is false.
    ///   @include example_is_convertible_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam From the type to convert to
    ///   @tparam To the type to convert from
    ///
    template<typename From, typename To>
    class is_nothrow_convertible final :    // --
        public bool_constant<details::check_is_nothrow_convertible<From, To>()>
    {};
}

#endif
