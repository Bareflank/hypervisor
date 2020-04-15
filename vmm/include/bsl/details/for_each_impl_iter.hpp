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

#ifndef BSL_DETAILS_FOR_EACH_IMPL_ITER_HPP
#define BSL_DETAILS_FOR_EACH_IMPL_ITER_HPP

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
        ///   @brief Provides the default implementation of for_each_impl_iter
        ///     which is used when a suitable version of FUNC cannot be found
        ///     (likely because the provided signature is not supported).
        ///
        /// <!-- template parameters -->
        ///   @tparam ITER1 The type of the first iterator.
        ///   @tparam ITER2 The type of the second iterator.
        ///   @tparam FUNC The function type that was provided by the user
        ///     to execute on each loop.
        ///   @tparam EO true if the provided function is only asking for a
        ///     reference to the current element in the loop.
        ///   @tparam EI true if the provided function is asking for a
        ///     reference to the current element in the loop and the current
        ///     index.
        ///
        template<
            typename ITER1,
            typename ITER2,
            typename FUNC,
            bool EO = is_invocable<FUNC, value_type_for<ITER1> &>::value,
            bool EI = is_invocable<FUNC, value_type_for<ITER1> &, bsl::uintmax>::value>
        class for_each_impl_iter final
        {
            static_assert(
                sizeof(FUNC) != sizeof(FUNC),    // NOLINT
                "the function you provided to bsl::for_each is invalid");

            /// <!-- description -->
            ///   @brief This function is only provided to reduce the garbage
            ///     the compiler spits out when an error occurs.
            ///
            /// <!-- inputs/outputs -->
            ///   @param begin points to the first element being iterated
            ///   @param end points to the last element being iterated
            ///   @param f the function to execute on each iteration
            ///
            static constexpr void
            call(ITER1 &&begin, ITER2 &&end, FUNC &&f) noexcept
            {
                bsl::discard(begin);
                bsl::discard(end);
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
        ///   @tparam ITER The type of the iterator used. Note that the default
        ///     implementation of for_each_impl_iter takes two iterator types
        ///     as it has to to match what bsl::for_each is given, but we
        ///     really want the iterators to be of the same type, so we only
        ///     define one iterator type here and then pass both to the default
        ///     for_each_impl_iter.
        ///   @tparam FUNC The function type that was provided by the user
        ///     to execute on each loop.
        ///
        template<typename ITER, typename FUNC>
        class for_each_impl_iter<ITER, ITER, FUNC, true, false> final
        {
            /// @brief reduces the verbosity of invoke_result_t
            using ret_type = invoke_result_t<FUNC, value_type_for<ITER> &>;

        public:
            /// <!-- description -->
            ///   @brief Executes the for loop as requested by the user of the
            ///     bsl::for_each API. Note that this function uses the
            ///     invoke_result_t to detect if the provided function returns
            ///     a bool or void to determine how to execute.
            ///
            /// <!-- inputs/outputs -->
            ///   @param begin points to the first element being iterated
            ///   @param end points to the last element being iterated
            ///   @param f the function to execute on each iteration
            ///
            static constexpr void
            call(ITER &&begin, ITER &&end, FUNC &&f) noexcept(
                is_nothrow_invocable<FUNC, value_type_for<ITER> &>::value)
            {
                for (ITER iter{begin}; iter < end; ++iter) {
                    if constexpr (is_bool<ret_type>::value) {
                        if (!invoke(bsl::forward<FUNC>(f), *iter.get_if())) {
                            break;
                        }
                    }
                    else {
                        invoke(bsl::forward<FUNC>(f), *iter.get_if());
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
        ///   @tparam ITER The type of the iterator used. Note that the default
        ///     implementation of for_each_impl_iter takes two iterator types
        ///     as it has to to match what bsl::for_each is given, but we
        ///     really want the iterators to be of the same type, so we only
        ///     define one iterator type here and then pass both to the default
        ///     for_each_impl_iter.
        ///   @tparam FUNC The function type that was provided by the user
        ///     to execute on each loop.
        ///
        template<typename ITER, typename FUNC>
        class for_each_impl_iter<ITER, ITER, FUNC, false, true> final
        {
            /// @brief reduces the verbosity of invoke_result_t
            using ret_type = invoke_result_t<FUNC, value_type_for<ITER> &, bsl::uintmax>;

        public:
            /// <!-- description -->
            ///   @brief Executes the for loop as requested by the user of the
            ///     bsl::for_each API. Note that this function uses the
            ///     invoke_result_t to detect if the provided function returns
            ///     a bool or void to determine how to execute.
            ///
            /// <!-- inputs/outputs -->
            ///   @param begin points to the first element being iterated
            ///   @param end points to the last element being iterated
            ///   @param f the function to execute on each iteration
            ///
            static constexpr void
            call(ITER &&begin, ITER &&end, FUNC &&f) noexcept(
                is_nothrow_invocable<FUNC, value_type_for<ITER> &, bsl::uintmax>::value)
            {
                for (ITER iter{begin}; iter < end; ++iter) {
                    if constexpr (is_bool<ret_type>::value) {
                        if (!invoke(bsl::forward<FUNC>(f), *iter.get_if(), iter.index())) {
                            break;
                        }
                    }
                    else {
                        invoke(bsl::forward<FUNC>(f), *iter.get_if(), iter.index());
                    }
                }
            }
        };
    }
}

#endif
