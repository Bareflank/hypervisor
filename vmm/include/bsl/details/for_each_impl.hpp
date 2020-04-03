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

#ifndef BSL_DETAILS_FOR_EACH_IMPL_HPP
#define BSL_DETAILS_FOR_EACH_IMPL_HPP

#include "for_each_impl_iter.hpp"
#include "for_each_impl_view.hpp"

#include "../discard.hpp"
#include "../forward.hpp"

namespace bsl
{
    namespace details
    {
        /// @class bsl::details::for_each_impl
        ///
        /// <!-- description -->
        ///   @brief Provides the main implementation of bsl::for_each. The
        ///     way this works is we dispatch to different implementations of
        ///     bsl::for_each based on the number of template arguments
        ///     provided (which is determined by the number of arguments
        ///     provided to bsl::for_each).
        ///
        /// <!-- template parameters -->
        ///   @tparam ARGS the types of arguments passed to bsl::for_each.
        ///
        template<typename... ARGS>
        class for_each_impl final
        {
            static_assert(
                sizeof(for_each_impl) != sizeof(for_each_impl),    // NOLINT
                "the view/iterators you provided to bsl::for_each are invalid");

            /// <!-- description -->
            ///   @brief This function is only provided to reduce the garbage
            ///     the compiler spits out when an error occurs.
            ///
            /// <!-- inputs/outputs -->
            ///   @param args the arguments passed to bsl::for_each
            ///
            static constexpr void
            call(ARGS &&... args) noexcept
            {
                bsl::discard(args...);
            }
        };

        /// @class bsl::details::for_each_impl
        ///
        /// <!-- description -->
        ///   @brief Provides the main implementation of bsl::for_each. The
        ///     way this works is we dispatch to different implementations of
        ///     bsl::for_each based on the number of template arguments
        ///     provided (which is determined by the number of arguments
        ///     provided to bsl::for_each). This version of for_each_impl
        ///     implements bsl::for_each for view type classes like bsl::span,
        ///     bsl::string_view and bsl::array.
        ///
        /// <!-- template parameters -->
        ///   @tparam VIEW The type of view being iterated
        ///   @tparam FUNC The function type that was provided by the user
        ///     to execute on each loop.
        ///
        template<typename VIEW, typename FUNC>
        class for_each_impl<VIEW, FUNC> final
        {
        public:
            /// <!-- description -->
            ///   @brief Forwards the request to the for_each_impl_view
            ///     which futher breaks apart the implemenation of the
            ///     bsl::for_each function for different types of functions
            ///     the user might provide.
            ///
            /// <!-- inputs/outputs -->
            ///   @param v the view to iterator over
            ///   @param f the function to execute on each iteration
            ///
            static constexpr void
            call(VIEW &&v, FUNC &&f) noexcept(noexcept(    // --
                for_each_impl_view<VIEW, FUNC>::call(bsl::forward<VIEW>(v), bsl::forward<FUNC>(f))))
            {
                for_each_impl_view<VIEW, FUNC>::call(bsl::forward<VIEW>(v), bsl::forward<FUNC>(f));
            }
        };

        /// @class bsl::details::for_each_impl
        ///
        /// <!-- description -->
        ///   @brief Provides the main implementation of bsl::for_each. The
        ///     way this works is we dispatch to different implementations of
        ///     bsl::for_each based on the number of template arguments
        ///     provided (which is determined by the number of arguments
        ///     provided to bsl::for_each). This version of for_each_impl
        ///     implements bsl::for_each for iterator types like the
        ///     contiguous iterators and reverse iterators.
        ///
        /// <!-- template parameters -->
        ///   @tparam ITER1 The type of the first iterator.
        ///   @tparam ITER2 The type of the second iterator.
        ///   @tparam FUNC The function type that was provided by the user
        ///     to execute on each loop.
        ///
        template<typename ITER1, typename ITER2, typename FUNC>
        class for_each_impl<ITER1, ITER2, FUNC> final
        {
        public:
            /// <!-- description -->
            ///   @brief Forwards the request to the for_each_impl_iter
            ///     which futher breaks apart the implemenation of the
            ///     bsl::for_each function for different types of functions
            ///     the user might provide.
            ///
            /// <!-- inputs/outputs -->
            ///   @param i1 points to the first element being iterated
            ///   @param i2 points to the last element being iterated
            ///   @param f the function to execute on each iteration
            ///
            static constexpr void
            call(ITER1 &&i1, ITER2 &&i2, FUNC &&f) noexcept(noexcept(    // --
                for_each_impl_iter<ITER1, ITER2, FUNC>::call(
                    bsl::forward<ITER1>(i1), bsl::forward<ITER2>(i2), bsl::forward<FUNC>(f))))
            {
                for_each_impl_iter<ITER1, ITER2, FUNC>::call(
                    bsl::forward<ITER1>(i1), bsl::forward<ITER2>(i2), bsl::forward<FUNC>(f));
            }
        };
    }
}

#endif
