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

#ifndef BSL_DETAILS_FOR_EACH_IMPL_VIEW_HPP
#define BSL_DETAILS_FOR_EACH_IMPL_VIEW_HPP

#include "value_type_for.hpp"

#include "../discard.hpp"
#include "../invoke_result.hpp"
#include "../is_bool.hpp"
#include "../is_invocable.hpp"
#include "../is_nothrow_invocable.hpp"

namespace bsl
{
    namespace details
    {
        /// @class
        ///
        /// <!-- description -->
        ///   @brief Provides the default implementation of for_each_impl_view
        ///     which is used when a suitable version of FUNC cannot be found
        ///     (likely because the provided signature is not supported).
        ///
        /// <!-- template parameters -->
        ///   @tparam VIEW The type of view being iterated
        ///   @tparam FUNC The function type that was provided by the user
        ///     to execute on each loop.
        ///   @tparam EO true if the provided function is only asking for a
        ///     reference to the current element in the loop.
        ///   @tparam EI true if the provided function is asking for a
        ///     reference to the current element in the loop and the current
        ///     index.
        ///
        template<
            typename VIEW,
            typename FUNC,
            bool EO = is_invocable<FUNC, value_type_for<VIEW> &>::value,
            bool EI = is_invocable<FUNC, value_type_for<VIEW> &, bsl::uintmax>::value>
        class for_each_impl_view final
        {
            static_assert(
                sizeof(FUNC) != sizeof(FUNC),    // NOLINT
                "the function you provided to bsl::for_each is invalid");

            /// <!-- description -->
            ///   @brief This function is only provided to reduce the garbage
            ///     the compiler spits out when an error occurs.
            ///
            /// <!-- inputs/outputs -->
            ///   @param v the view to iterator over
            ///   @param f the function to execute on each iteration
            ///
            static constexpr void
            call(VIEW &&v, FUNC &&f) noexcept
            {
                bsl::discard(v);
                bsl::discard(f);
            }
        };

        /// @class
        ///
        /// <!-- description -->
        ///   @brief Provides the implementation of the call function for
        ///     when the user is asking for a reference to the current element
        ///     in the loop.
        ///
        /// <!-- template parameters -->
        ///   @tparam VIEW The type of the view being iterated.
        ///   @tparam FUNC The function type that was provided by the user
        ///     to execute on each loop.
        ///
        template<typename VIEW, typename FUNC>
        class for_each_impl_view<VIEW, FUNC, true, false> final
        {
            /// @brief reduces the verbosity of invoke_result_t
            using ret_type = invoke_result_t<FUNC, value_type_for<VIEW> &>;

        public:
            /// <!-- description -->
            ///   @brief Executes the for loop as requested by the user of the
            ///     bsl::for_each API. Note that this function uses the
            ///     invoke_result_t to detect if the provided function returns
            ///     a bool or void to determine how to execute.
            ///
            /// <!-- inputs/outputs -->
            ///   @param v the view to iterator over
            ///   @param f the function to execute on each iteration
            ///
            static constexpr void
            call(VIEW &&v, FUNC &&f) noexcept(
                is_nothrow_invocable<FUNC, value_type_for<VIEW> &>::value)
            {
                for (bsl::uintmax i{}; i < v.size(); ++i) {
                    if constexpr (is_bool<ret_type>::value) {
                        if (!invoke(bsl::forward<FUNC>(f), *v.at_if(i))) {
                            break;
                        }
                    }
                    else {
                        invoke(bsl::forward<FUNC>(f), *v.at_if(i));
                    }
                }
            }
        };

        /// @class
        ///
        /// <!-- description -->
        ///   @brief Provides the implementation of the call function for
        ///     when the user is asking for a reference to the current element
        ///     in the loop and the current index.
        ///
        /// <!-- template parameters -->
        ///   @tparam VIEW The type of the view being iterated.
        ///   @tparam FUNC The function type that was provided by the user
        ///     to execute on each loop.
        ///
        template<typename VIEW, typename FUNC>
        class for_each_impl_view<VIEW, FUNC, false, true> final
        {
            /// @brief reduces the verbosity of invoke_result_t
            using ret_type = invoke_result_t<FUNC, value_type_for<VIEW> &, bsl::uintmax>;

        public:
            /// <!-- description -->
            ///   @brief Executes the for loop as requested by the user of the
            ///     bsl::for_each API. Note that this function uses the
            ///     invoke_result_t to detect if the provided function returns
            ///     a bool or void to determine how to execute.
            ///
            /// <!-- inputs/outputs -->
            ///   @param v the view to iterator over
            ///   @param f the function to execute on each iteration
            ///
            static constexpr void
            call(VIEW &&v, FUNC &&f) noexcept(
                is_nothrow_invocable<FUNC, value_type_for<VIEW> &, bsl::uintmax>::value)
            {
                for (bsl::uintmax i{}; i < v.size(); ++i) {
                    if constexpr (is_bool<ret_type>::value) {
                        if (!invoke(bsl::forward<FUNC>(f), *v.at_if(i), i)) {
                            break;
                        }
                    }
                    else {
                        invoke(bsl::forward<FUNC>(f), *v.at_if(i), i);
                    }
                }
            }
        };
    }
}

#endif
