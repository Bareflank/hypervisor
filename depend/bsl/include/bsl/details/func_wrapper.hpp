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

#ifndef BSL_DETAILS_FUNC_WRAPPER_HPP
#define BSL_DETAILS_FUNC_WRAPPER_HPP

#include "../forward.hpp"

namespace bsl
{
    namespace details
    {
        template<typename>
        class func_wrapper;

        /// @class bsl::details::func_wrapper
        ///
        /// <!-- description -->
        ///   @brief Wraps a regular function call.
        ///
        /// <!-- template parameters -->
        ///   @tparam R the return type of the function being wrapped
        ///   @tparam ARGS the arg types of the function being wrapped
        ///
        template<typename R, typename... ARGS>
        class func_wrapper<R(ARGS...)> final : public base_wrapper<R(ARGS...)>
        {
            /// @brief stores a pointer to the wrapped function
            R (*m_func)(ARGS...);

        public:
            /// <!-- description -->
            ///   @brief Creates a bsl::details::func_wrapper given a pointer
            ///     to a regular function. This function pointer is stored,
            ///     and later called by the overloaded call function.
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            /// <!-- inputs/outputs -->
            ///   @param func a pointer to a regular function
            ///
            explicit constexpr func_wrapper(R (*const func)(ARGS...)) noexcept
                : base_wrapper<R(ARGS...)>{}, m_func{func}
            {}

            /// <!-- description -->
            ///   @brief Calls the wrapped function by passing "args" to the
            ///     function and returing the result.
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            /// <!-- inputs/outputs -->
            ///   @param args the arguments to pass to the wrapped function
            ///   @return returns the result of the wrapped function
            ///
            /// <!-- exceptions -->
            ///   @throw throws if the wrapped function throws
            ///
            [[nodiscard]] R
            call(ARGS &&... args) const noexcept(false) final
            {
                return m_func(bsl::forward<ARGS>(args)...);
            }
        };

        /// @class bsl::details::func_wrapper
        ///
        /// <!-- description -->
        ///   @brief Wraps a regular function call.
        ///
        /// <!-- template parameters -->
        ///   @tparam R the return type of the function being wrapped
        ///   @tparam ARGS the arg types of the function being wrapped
        ///
        template<typename R, typename... ARGS>
        class func_wrapper<R(ARGS...) noexcept> final : public base_wrapper<R(ARGS...) noexcept>
        {
            /// @brief stores a pointer to the wrapped function
            R (*m_func)(ARGS...) noexcept;

        public:
            /// <!-- description -->
            ///   @brief Creates a bsl::details::func_wrapper given a pointer
            ///     to a regular function. This function pointer is stored,
            ///     and later called by the overloaded call function.
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            /// <!-- inputs/outputs -->
            ///   @param func a pointer to a regular function
            ///
            explicit constexpr func_wrapper(R (*const func)(ARGS...) noexcept) noexcept
                : base_wrapper<R(ARGS...) noexcept>{}, m_func{func}
            {}

            /// <!-- description -->
            ///   @brief Calls the wrapped function by passing "args" to the
            ///     function and returing the result.
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            /// <!-- inputs/outputs -->
            ///   @param args the arguments to pass to the wrapped function
            ///   @return returns the result of the wrapped function
            ///
            [[nodiscard]] R
            call(ARGS &&... args) const noexcept final
            {
                return m_func(bsl::forward<ARGS>(args)...);
            }
        };
    }
}

#endif
