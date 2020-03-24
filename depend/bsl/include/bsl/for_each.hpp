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
/// @file for_each.hpp
///

#ifndef BSL_FOREACH_HPP
#define BSL_FOREACH_HPP

#include "cstdint.hpp"
#include "enable_if.hpp"
#include "forward.hpp"
#include "invoke.hpp"
#include "is_invocable.hpp"
#include "is_nothrow_invocable.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief Loops through the array, and for each element in the array,
    ///     calls the provided function "f" with a reference to the array
    ///     element as well as the index of the element. Note that this version
    ///     loops through the array from 0 to N - 1.
    ///   @include example_for_each_overview.hpp
    ///
    ///   SUPPRESSION: PRQA 2023 - exception required
    ///   - We suppress this because A13-3-1 states that you should not
    ///     overload functions that contain a forwarding reference because
    ///     it is confusing to the user. In this case, there is nothing
    ///     ambiguous about this situation as we are not overloading the
    ///     forewarding reference itself, which is the only way to define a
    ///     function pointer that accepts lambdas with capture lists.
    ///     The examples that demonstrate a problem overload the forwarding
    ///     reference itself, which is what creates the ambiguity.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the array's element type
    ///   @tparam N the total number of elements in the array
    ///   @tparam FUNC The type the defines the function "f"
    ///   @param array the array to loop over
    ///   @param f the function f to call
    ///
    template<typename T, bsl::uintmax N, typename FUNC>
    constexpr void
    for_each(T (&array)[N], FUNC &&f)    // PRQA S 2023 // NOLINT
        noexcept(is_nothrow_invocable<FUNC, T &, bsl::uintmax>::value)
    {
        static_assert(is_invocable<FUNC, T &, bsl::uintmax>::value);

        for (bsl::uintmax i{}; i < N; ++i) {
            invoke(bsl::forward<FUNC>(f), array[i], i);
        }
    }

    /// <!-- description -->
    ///   @brief Loops through the array, and for each element in the array,
    ///     calls the provided function "f" with a reference to the array
    ///     element as well as the index of the element. Note that this version
    ///     loops through the array from 0 to N - 1.
    ///   @include example_for_each_overview.hpp
    ///
    ///   SUPPRESSION: PRQA 2023 - exception required
    ///   - We suppress this because A13-3-1 states that you should not
    ///     overload functions that contain a forwarding reference because
    ///     it is confusing to the user. In this case, there is nothing
    ///     ambiguous about this situation as we are not overloading the
    ///     forewarding reference itself, which is the only way to define a
    ///     function pointer that accepts lambdas with capture lists.
    ///     The examples that demonstrate a problem overload the forwarding
    ///     reference itself, which is what creates the ambiguity.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the array's element type
    ///   @tparam N the total number of elements in the array
    ///   @tparam FUNC The type the defines the function "f"
    ///   @param array the array to loop over
    ///   @param pos the stating position of the loop
    ///   @param f the function f to call
    ///
    template<typename T, bsl::uintmax N, typename FUNC>
    constexpr void
    for_each(T (&array)[N], bsl::uintmax pos, FUNC &&f)    // PRQA S 2023 // NOLINT
        noexcept(is_nothrow_invocable<FUNC, T &, bsl::uintmax>::value)
    {
        static_assert(is_invocable<FUNC, T &, bsl::uintmax>::value);

        for (bsl::uintmax i{pos}; i < N; ++i) {
            invoke(bsl::forward<FUNC>(f), array[i], i);
        }
    }

    /// <!-- description -->
    ///   @brief Loops through the array, and for each element in the array,
    ///     calls the provided function "f" with a reference to the array
    ///     element as well as the index of the element. Note that this version
    ///     loops through the array from 0 to N - 1.
    ///   @include example_for_each_overview.hpp
    ///
    ///   SUPPRESSION: PRQA 2023 - exception required
    ///   - We suppress this because A13-3-1 states that you should not
    ///     overload functions that contain a forwarding reference because
    ///     it is confusing to the user. In this case, there is nothing
    ///     ambiguous about this situation as we are not overloading the
    ///     forewarding reference itself, which is the only way to define a
    ///     function pointer that accepts lambdas with capture lists.
    ///     The examples that demonstrate a problem overload the forwarding
    ///     reference itself, which is what creates the ambiguity.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the array's element type
    ///   @tparam N the total number of elements in the array
    ///   @tparam FUNC The type the defines the function "f"
    ///   @param array the array to loop over
    ///   @param pos the stating position of the loop
    ///   @param count the number of iterations to make make in the loop
    ///   @param f the function f to call
    ///
    template<typename T, bsl::uintmax N, typename FUNC>
    constexpr void
    for_each(                        // PRQA S 2023
        T (&array)[N],               // NOLINT
        bsl::uintmax const pos,      // --
        bsl::uintmax const count,    // --
        FUNC &&f) noexcept(is_nothrow_invocable<FUNC, T &, bsl::uintmax>::value)
    {
        static_assert(is_invocable<FUNC, T &, bsl::uintmax>::value);

        if (pos >= N) {
            return;
        }

        if (count > N - pos) {
            return;
        }

        for (bsl::uintmax i{pos}; i < pos + count; ++i) {
            invoke(bsl::forward<FUNC>(f), array[i], i);
        }
    }

    /// <!-- description -->
    ///   @brief Loops through the array, and for each element in the array,
    ///     calls the provided function "f" with a reference to the array
    ///     element as well as the index of the element. Note that this version
    ///     loops through the array from 0 to N - 1.
    ///   @include example_for_each_overview.hpp
    ///
    ///   SUPPRESSION: PRQA 2023 - exception required
    ///   - We suppress this because A13-3-1 states that you should not
    ///     overload functions that contain a forwarding reference because
    ///     it is confusing to the user. In this case, there is nothing
    ///     ambiguous about this situation as we are not overloading the
    ///     forewarding reference itself, which is the only way to define a
    ///     function pointer that accepts lambdas with capture lists.
    ///     The examples that demonstrate a problem overload the forwarding
    ///     reference itself, which is what creates the ambiguity.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the array's element type
    ///   @tparam N the total number of elements in the array
    ///   @tparam FUNC The type the defines the function "f"
    ///   @param array the array to loop over
    ///   @param f the function f to call
    ///
    template<typename T, bsl::uintmax N, typename FUNC>
    constexpr void
    for_each(T const (&array)[N], FUNC &&f)    // PRQA S 2023 // NOLINT
        noexcept(is_nothrow_invocable<FUNC, T const &, bsl::uintmax>::value)
    {
        static_assert(is_invocable<FUNC, T &, bsl::uintmax>::value);

        for (bsl::uintmax i{}; i < N; ++i) {
            invoke(bsl::forward<FUNC>(f), array[i], i);
        }
    }

    /// <!-- description -->
    ///   @brief Loops through the array, and for each element in the array,
    ///     calls the provided function "f" with a reference to the array
    ///     element as well as the index of the element. Note that this version
    ///     loops through the array from 0 to N - 1.
    ///   @include example_for_each_overview.hpp
    ///
    ///   SUPPRESSION: PRQA 2023 - exception required
    ///   - We suppress this because A13-3-1 states that you should not
    ///     overload functions that contain a forwarding reference because
    ///     it is confusing to the user. In this case, there is nothing
    ///     ambiguous about this situation as we are not overloading the
    ///     forewarding reference itself, which is the only way to define a
    ///     function pointer that accepts lambdas with capture lists.
    ///     The examples that demonstrate a problem overload the forwarding
    ///     reference itself, which is what creates the ambiguity.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the array's element type
    ///   @tparam N the total number of elements in the array
    ///   @tparam FUNC The type the defines the function "f"
    ///   @param array the array to loop over
    ///   @param pos the stating position of the loop
    ///   @param f the function f to call
    ///
    template<typename T, bsl::uintmax N, typename FUNC>
    constexpr void
    for_each(T const (&array)[N], bsl::uintmax const pos, FUNC &&f)    // PRQA S 2023 // NOLINT
        noexcept(is_nothrow_invocable<FUNC, T const &, bsl::uintmax>::value)
    {
        static_assert(is_invocable<FUNC, T &, bsl::uintmax>::value);

        for (bsl::uintmax i{pos}; i < N; ++i) {
            invoke(bsl::forward<FUNC>(f), array[i], i);
        }
    }

    /// <!-- description -->
    ///   @brief Loops through the array, and for each element in the array,
    ///     calls the provided function "f" with a reference to the array
    ///     element as well as the index of the element. Note that this version
    ///     loops through the array from 0 to N - 1.
    ///   @include example_for_each_overview.hpp
    ///
    ///   SUPPRESSION: PRQA 2023 - exception required
    ///   - We suppress this because A13-3-1 states that you should not
    ///     overload functions that contain a forwarding reference because
    ///     it is confusing to the user. In this case, there is nothing
    ///     ambiguous about this situation as we are not overloading the
    ///     forewarding reference itself, which is the only way to define a
    ///     function pointer that accepts lambdas with capture lists.
    ///     The examples that demonstrate a problem overload the forwarding
    ///     reference itself, which is what creates the ambiguity.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the array's element type
    ///   @tparam N the total number of elements in the array
    ///   @tparam FUNC The type the defines the function "f"
    ///   @param array the array to loop over
    ///   @param pos the stating position of the loop
    ///   @param count the number of iterations to make make in the loop
    ///   @param f the function f to call
    ///
    template<typename T, bsl::uintmax N, typename FUNC>
    constexpr void
    for_each(                        // PRQA S 2023
        T const (&array)[N],         // NOLINT
        bsl::uintmax const pos,      // --
        bsl::uintmax const count,    // --
        FUNC &&f) noexcept(is_nothrow_invocable<FUNC, T const &, bsl::uintmax>::value)
    {
        static_assert(is_invocable<FUNC, T &, bsl::uintmax>::value);

        if (pos >= N) {
            return;
        }

        if (count > N - pos) {
            return;
        }

        for (bsl::uintmax i{pos}; i < pos + count; ++i) {
            invoke(bsl::forward<FUNC>(f), array[i], i);
        }
    }
}

#endif
