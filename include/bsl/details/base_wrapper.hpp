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

#ifndef BSL_DETAILS_BASE_WRAPPER_HPP
#define BSL_DETAILS_BASE_WRAPPER_HPP

namespace bsl
{
    namespace details
    {
        template<typename>
        class base_wrapper;

        /// @class bsl::details::base_wrapper
        ///
        /// <!-- description -->
        ///   @brief Provides the base class implementation for the function,
        ///     member function and const member function wrappers.
        ///     Specifically, this ensures each wrapper implements that same
        ///     call function so that a bsl::function only has to execute
        ///     the base class's call function without knowing if the
        ///     function is a normal function or a member function.
        ///
        /// <!-- template parameters -->
        ///   @tparam R the return type of the function being wrapped
        ///   @tparam ARGS the arg types of the function being wrapped
        ///
        template<typename R, typename... ARGS>
        class base_wrapper<R(ARGS...)>
        {
        public:
            /// <!-- description -->
            ///   @brief default constructor
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            constexpr base_wrapper() noexcept = default;

            /// <!-- description -->
            ///   @brief virtual default destructor
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            virtual ~base_wrapper() noexcept = default;

            /// <!-- description -->
            ///   @brief Pure virtual "call" function that is overloaded
            ///     by the function, member function and const member function
            ///     wrappers. This function is called by the bsl::function to
            ///     execute a wrapped function.
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            /// <!-- inputs/outputs -->
            ///   @param args the arguments to pass to the wrapped function
            ///   @return the return value of the wrapped function
            ///
            /// <!-- exceptions -->
            ///   @throw throws if the wrapped function throws
            ///
            [[nodiscard]] virtual R call(ARGS &&... args) const noexcept(false) = 0;

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
            constexpr base_wrapper(base_wrapper const &o) noexcept = default;

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
            constexpr base_wrapper(base_wrapper &&o) noexcept = default;

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
            [[maybe_unused]] constexpr base_wrapper &
            operator=(base_wrapper const &o) &noexcept = default;

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
            [[maybe_unused]] constexpr base_wrapper &
            operator=(base_wrapper &&o) &noexcept = default;
        };

        /// @class bsl::details::base_wrapper
        ///
        /// <!-- description -->
        ///   @brief Provides the base class implementation for the function,
        ///     member function and const member function wrappers.
        ///     Specifically, this ensures each wrapper implements that same
        ///     call function so that a bsl::function only has to execute
        ///     the base class's call function without knowing if the
        ///     function is a normal function or a member function.
        ///
        /// <!-- template parameters -->
        ///   @tparam R the return type of the function being wrapped
        ///   @tparam ARGS the arg types of the function being wrapped
        ///
        template<typename R, typename... ARGS>
        class base_wrapper<R(ARGS...) noexcept>
        {
        public:
            /// <!-- description -->
            ///   @brief default constructor
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            constexpr base_wrapper() noexcept = default;

            /// <!-- description -->
            ///   @brief virtual default destructor
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            virtual ~base_wrapper() noexcept = default;

            /// <!-- description -->
            ///   @brief Pure virtual "call" function that is overloaded
            ///     by the function, member function and const member function
            ///     wrappers. This function is called by the bsl::function to
            ///     execute a wrapped function.
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            /// <!-- inputs/outputs -->
            ///   @param args the arguments to pass to the wrapped function
            ///   @return the return value of the wrapped function
            ///
            [[nodiscard]] virtual R call(ARGS &&... args) const noexcept = 0;

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
            constexpr base_wrapper(base_wrapper const &o) noexcept = default;

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
            constexpr base_wrapper(base_wrapper &&o) noexcept = default;

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
            [[maybe_unused]] constexpr base_wrapper &
            operator=(base_wrapper const &o) &noexcept = default;

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
            [[maybe_unused]] constexpr base_wrapper &
            operator=(base_wrapper &&o) &noexcept = default;
        };
    }
}

#endif
