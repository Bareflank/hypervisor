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
/// @file delegate.hpp
///

#ifndef BSL_DELEGATE_HPP
#define BSL_DELEGATE_HPP

#include "details/cast.hpp"
#include "details/base_wrapper.hpp"
#include "details/func_wrapper.hpp"
#include "details/memfunc_wrapper.hpp"
#include "details/cmemfunc_wrapper.hpp"

#include "aligned_storage.hpp"
#include "construct_at.hpp"
#include "result.hpp"

namespace bsl
{
    /// @cond doxygen off

    /// @brief delegate prototype
    template<typename>
    class delegate;

    /// @endcond doxygen on

    /// <!-- description -->
    ///   @brief Implements a simplified version of std::function. Unlike
    ///     std::function, a bsl::delegate has the following differences:
    ///     - Lambda functions, and binding in general are not supported.
    ///       Instead, either use a function pointer, or a member function
    ///       pointer. The reason is this implementation attempts to reduce
    ///       the overhead of std::function, and dynamic memory is not
    ///       supported, so the bsl::delegate has a fixed amount of memory
    ///       that it can support for wrapping.
    ///     - Operator bool is not supported as AUTOSAR does not allow for
    ///       the use of the conversion operator. Instead, use valid().
    ///     - Target access, non-member and helper functions are not supported.
    ///     - Functions marked as "noexcept" are supported. If the function
    ///       is marked as noexcept, the resulting bsl::delegate's functor
    ///       will also be marked as noexcept and vice versa.
    ///   @include example_delegate_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam R the return value of the delegate being wrapped
    ///   @tparam ARGS The arguments to the delegate being wrapped
    ///
    template<typename R, typename... ARGS>
    class delegate<R(ARGS...)> final
    {
        /// @brief stores whether or not this delegate is valid
        bool m_valid;
        /// @brief stores the call wrapper
        aligned_storage_t<sizeof(void *) * 3> m_store;

    public:
        /// <!-- description -->
        ///   @brief Provides support for ensuring that a bsl::delegate is a
        ///     POD type, allowing it to be defined as a global resource.
        ///     When used globally, a bsl::delegate should not include {},
        ///     as required by AUTOSAR. The OS will automatically zero
        ///     initialize the bsl::delegate for you, marking the bsl::delegate
        ///     as invalid. If you use this constructor locally, you must
        ///     include {} to ensure the bsl::delegate is initialized, which
        ///     most compilers will warn about.
        ///   @include delegate/example_delegate_default_constructor.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        delegate() noexcept = default;

        /// <!-- description -->
        ///   @brief Creates a bsl::delegate from a function pointer. If the
        ///     function pointer is a nullptr, the resulting bsl::delegate
        ///     is marked as invalid, and will always return an error when
        ///     executed.
        ///   @include delegate/example_delegate_constructor_func.hpp
        ///
        ///   SUPPRESSION: PRQA 2180 - false positive
        ///   - We suppress this because A12-1-4 states that all constructors
        ///     that are callable from a fundamental type should be marked as
        ///     explicit. This is not a fundamental type and there for does
        ///     not apply.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param func a pointer to the delegate being wrapped
        ///
        delegate(R (*const func)(ARGS...)) noexcept    // PRQA S 2180 // NOLINT
            : m_valid{nullptr != func}, m_store{}
        {
            static_assert(sizeof(m_store) >= sizeof(details::func_wrapper<R(ARGS...)>));

            if (m_valid) {
                construct_at<details::func_wrapper<R(ARGS...)>>(&m_store, func);
            }
        }

        /// <!-- description -->
        ///   @brief Creates a bsl::delegate from a member function pointer. If
        ///     the function pointer is a nullptr, the resulting bsl::delegate
        ///     is marked as invalid, and will always return an error when
        ///     executed.
        ///   @include delegate/example_delegate_constructor_memfunc.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param t the object to execute the member function from
        ///   @param func a pointer to the delegate being wrapped
        ///
        template<typename T, typename U>
        delegate(T &t, R (U::*const func)(ARGS...)) noexcept    // --
            : m_valid{nullptr != func}, m_store{}
        {
            static_assert(sizeof(m_store) >= sizeof(details::memfunc_wrapper<T, R(ARGS...)>));

            if (m_valid) {
                construct_at<details::memfunc_wrapper<T, R(ARGS...)>>(&m_store, t, func);
            }
        }

        /// <!-- description -->
        ///   @brief Creates a bsl::delegate from a const member function
        ///     pointer. If the function pointer is a nullptr, the resulting
        ///     bsl::delegate is marked as invalid, and will always return an
        ///     error when executed.
        ///   @include delegate/example_delegate_constructor_cmemfunc.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param t the object to execute the member function from
        ///   @param func a pointer to the delegate being wrapped
        ///
        template<typename T, typename U>
        delegate(T const &t, R (U::*const func)(ARGS...) const) noexcept    // --
            : m_valid{nullptr != func}, m_store{}
        {
            static_assert(sizeof(m_store) >= sizeof(details::cmemfunc_wrapper<T, R(ARGS...)>));

            if (m_valid) {
                construct_at<details::cmemfunc_wrapper<T, R(ARGS...)>>(&m_store, t, func);
            }
        }

        /// <!-- description -->
        ///   @brief Execute the bsl::delegate by calling the wrapped function
        ///     with "args" and returning the result.
        ///   @include delegate/example_delegate_functor.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param args the arguments to pass to the wrapped function
        ///   @return returns the results of the wrapped function
        ///
        /// <!-- inputs/outputs -->
        ///   @throw throws if the wrapped function throws
        ///
        [[nodiscard]] result<R>
        operator()(ARGS &&... args) const noexcept(false)
        {
            if (m_valid) {
                details::base_wrapper<R(ARGS...)> const *const ptr{
                    details::cast<details::base_wrapper<R(ARGS...)>>(&m_store)};

                return {bsl::in_place, ptr->call(bsl::forward<ARGS>(args)...)};
            }

            return {bsl::errc_bad_function};
        }

        /// <!-- description -->
        ///   @brief If the bsl::delegate is valid, returns true, otherwise
        ///     returns false.
        ///   @include delegate/example_delegate_valid.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return If the bsl::delegate is valid, returns true, otherwise
        ///     returns false.
        ///
        [[nodiscard]] bool
        valid() const noexcept
        {
            return m_valid;
        }
    };

    /// @cond doxygen off

    /// @class bsl::delegate
    ///
    /// <!-- description -->
    ///   @brief Implements a simplified version of std::function. Unlike
    ///     std::function, a bsl::delegate has the following differences:
    ///     - Lambda functions, and binding in general are not supported.
    ///       Instead, either use a function pointer, or a member function
    ///       pointer. The reason is this implementation attempts to reduce
    ///       the overhead of std::function, and dynamic memory is not
    ///       supported, so the bsl::delegate has a fixed amount of memory
    ///       that it can support for wrapping.
    ///     - Operator bool is not supported as AUTOSAR does not allow for
    ///       the use of the conversion operator. Instead, use valid().
    ///     - Target access, non-member and helper functions are not supported.
    ///     - Functions marked as "noexcept" are supported. If the function
    ///       is marked as noexcept, the resulting bsl::delegate's functor
    ///       will also be marked as noexcept and vice versa.
    ///   @include example_delegate_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam R the return value of the delegate being wrapped
    ///   @tparam ARGS The arguments to the delegate being wrapped
    ///
    template<typename R, typename... ARGS>
    class delegate<R(ARGS...) noexcept> final
    {
        /// @brief stores whether or not this delegate is valid
        bool m_valid;
        /// @brief stores the call wrapper
        aligned_storage_t<sizeof(void *) * 3> m_store;

    public:
        /// <!-- description -->
        ///   @brief Provides support for ensuring that a bsl::delegate is a
        ///     POD type, allowing it to be defined as a global resource.
        ///     When used globally, a bsl::delegate should not include {},
        ///     as required by AUTOSAR. The OS will automatically zero
        ///     initialize the bsl::delegate for you, marking the bsl::delegate
        ///     as invalid. If you use this constructor locally, you must
        ///     include {} to ensure the bsl::delegate is initialized, which
        ///     most compilers will warn about.
        ///   @include delegate/example_delegate_default_constructor.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        delegate() noexcept = default;

        /// <!-- description -->
        ///   @brief Creates a bsl::delegate from a function pointer. If the
        ///     function pointer is a nullptr, the resulting bsl::delegate
        ///     is marked as invalid, and will always return an error when
        ///     executed.
        ///   @include delegate/example_delegate_constructor_func.hpp
        ///
        ///   SUPPRESSION: PRQA 2180 - false positive
        ///   - We suppress this because A12-1-4 states that all constructors
        ///     that are callable from a fundamental type should be marked as
        ///     explicit. This is not a fundamental type and there for does
        ///     not apply.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param func a pointer to the delegate being wrapped
        ///
        delegate(R (*const func)(ARGS...) noexcept) noexcept    // PRQA S 2180 // NOLINT
            : m_valid{nullptr != func}, m_store{}
        {
            static_assert(sizeof(m_store) >= sizeof(details::func_wrapper<R(ARGS...)>));

            if (m_valid) {
                construct_at<details::func_wrapper<R(ARGS...) noexcept>>(&m_store, func);
            }
        }

        /// <!-- description -->
        ///   @brief Creates a bsl::delegate from a member function pointer. If
        ///     the function pointer is a nullptr, the resulting bsl::delegate
        ///     is marked as invalid, and will always return an error when
        ///     executed.
        ///   @include delegate/example_delegate_constructor_memfunc.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param t the object to execute the member function from
        ///   @param func a pointer to the delegate being wrapped
        ///
        template<typename T, typename U>
        delegate(T &t, R (U::*const func)(ARGS...) noexcept) noexcept    // --
            : m_valid{nullptr != func}, m_store{}
        {
            static_assert(sizeof(m_store) >= sizeof(details::memfunc_wrapper<T, R(ARGS...)>));

            if (m_valid) {
                construct_at<details::memfunc_wrapper<T, R(ARGS...) noexcept>>(&m_store, t, func);
            }
        }

        /// <!-- description -->
        ///   @brief Creates a bsl::delegate from a const member function
        ///     pointer. If the function pointer is a nullptr, the resulting
        ///     bsl::delegate is marked as invalid, and will always return an
        ///     error when executed.
        ///   @include delegate/example_delegate_constructor_cmemfunc.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param t the object to execute the member function from
        ///   @param func a pointer to the delegate being wrapped
        ///
        template<typename T, typename U>
        delegate(T const &t, R (U::*const func)(ARGS...) const noexcept) noexcept    // --
            : m_valid{nullptr != func}, m_store{}
        {
            static_assert(sizeof(m_store) >= sizeof(details::cmemfunc_wrapper<T, R(ARGS...)>));

            if (m_valid) {
                construct_at<details::cmemfunc_wrapper<T, R(ARGS...) noexcept>>(&m_store, t, func);
            }
        }

        /// <!-- description -->
        ///   @brief Execute the bsl::delegate by calling the wrapped function
        ///     with "args" and returning the result.
        ///   @include delegate/example_delegate_functor.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param args the arguments to pass to the wrapped function
        ///   @return returns the results of the wrapped function
        ///
        [[nodiscard]] result<R>
        operator()(ARGS &&... args) const noexcept
        {
            if (m_valid) {
                details::base_wrapper<R(ARGS...) noexcept> const *const ptr{
                    details::cast<details::base_wrapper<R(ARGS...) noexcept>>(&m_store)};

                return {bsl::in_place, ptr->call(bsl::forward<ARGS>(args)...)};
            }

            return {bsl::errc_bad_function};
        }

        /// <!-- description -->
        ///   @brief If the bsl::delegate is valid, returns true, otherwise
        ///     returns false.
        ///   @include delegate/example_delegate_valid.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return If the bsl::delegate is valid, returns true, otherwise
        ///     returns false.
        ///
        [[nodiscard]] bool
        valid() const noexcept
        {
            return m_valid;
        }
    };

    /// @class bsl::delegate<void(ARGS...)>
    ///
    /// <!-- description -->
    ///   @brief Implements a simplified version of std::function. Unlike
    ///     std::function, a bsl::delegate has the following differences:
    ///     - Lambda functions, and binding in general are not supported.
    ///       Instead, either use a function pointer, or a member function
    ///       pointer. The reason is this implementation attempts to reduce
    ///       the overhead of std::function, and dynamic memory is not
    ///       supported, so the bsl::delegate has a fixed amount of memory
    ///       that it can support for wrapping.
    ///     - Operator bool is not supported as AUTOSAR does not allow for
    ///       the use of the conversion operator. Instead, use valid().
    ///     - Target access, non-member and helper functions are not supported.
    ///     - Functions marked as "noexcept" are supported. If the function
    ///       is marked as noexcept, the resulting bsl::delegate's functor
    ///       will also be marked as noexcept and vice versa.
    ///   @include example_delegate_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam ARGS The arguments to the delegate being wrapped
    ///
    template<typename... ARGS>
    class delegate<void(ARGS...)> final
    {
        /// @brief stores whether or not this delegate is valid
        bool m_valid;
        /// @brief stores the call wrapper
        aligned_storage_t<sizeof(void *) * 3> m_store;

    public:
        /// <!-- description -->
        ///   @brief Provides support for ensuring that a bsl::delegate is a
        ///     POD type, allowing it to be defined as a global resource.
        ///     When used globally, a bsl::delegate should not include {},
        ///     as required by AUTOSAR. The OS will automatically zero
        ///     initialize the bsl::delegate for you, marking the bsl::delegate
        ///     as invalid. If you use this constructor locally, you must
        ///     include {} to ensure the bsl::delegate is initialized, which
        ///     most compilers will warn about.
        ///   @include delegate/example_delegate_default_constructor.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        delegate() noexcept = default;

        /// <!-- description -->
        ///   @brief Creates a bsl::delegate from a function pointer. If the
        ///     function pointer is a nullptr, the resulting bsl::delegate
        ///     is marked as invalid, and will always return an error when
        ///     executed.
        ///   @include delegate/example_delegate_constructor_func.hpp
        ///
        ///   SUPPRESSION: PRQA 2180 - false positive
        ///   - We suppress this because A12-1-4 states that all constructors
        ///     that are callable from a fundamental type should be marked as
        ///     explicit. This is not a fundamental type and there for does
        ///     not apply.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param func a pointer to the delegate being wrapped
        ///
        delegate(void (*const func)(ARGS...)) noexcept    // PRQA S 2180 // NOLINT
            : m_valid{nullptr != func}, m_store{}
        {
            static_assert(sizeof(m_store) >= sizeof(details::func_wrapper<void(ARGS...)>));

            if (m_valid) {
                construct_at<details::func_wrapper<void(ARGS...)>>(&m_store, func);
            }
        }

        /// <!-- description -->
        ///   @brief Creates a bsl::delegate from a member function pointer. If
        ///     the function pointer is a nullptr, the resulting bsl::delegate
        ///     is marked as invalid, and will always return an error when
        ///     executed.
        ///   @include delegate/example_delegate_constructor_memfunc.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param t the object to execute the member function from
        ///   @param func a pointer to the delegate being wrapped
        ///
        template<typename T, typename U>
        delegate(T &t, void (U::*const func)(ARGS...)) noexcept    // --
            : m_valid{nullptr != func}, m_store{}
        {
            static_assert(sizeof(m_store) >= sizeof(details::memfunc_wrapper<T, void(ARGS...)>));

            if (m_valid) {
                construct_at<details::memfunc_wrapper<T, void(ARGS...)>>(&m_store, t, func);
            }
        }

        /// <!-- description -->
        ///   @brief Creates a bsl::delegate from a const member function
        ///     pointer. If the function pointer is a nullptr, the resulting
        ///     bsl::delegate is marked as invalid, and will always return an
        ///     error when executed.
        ///   @include delegate/example_delegate_constructor_cmemfunc.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param t the object to execute the member function from
        ///   @param func a pointer to the delegate being wrapped
        ///
        template<typename T, typename U>
        delegate(T const &t, void (U::*const func)(ARGS...) const) noexcept    // --
            : m_valid{nullptr != func}, m_store{}
        {
            static_assert(sizeof(m_store) >= sizeof(details::cmemfunc_wrapper<T, void(ARGS...)>));

            if (m_valid) {
                construct_at<details::cmemfunc_wrapper<T, void(ARGS...)>>(&m_store, t, func);
            }
        }

        /// <!-- description -->
        ///   @brief Execute the bsl::delegate by calling the wrapped function
        ///     with "args".
        ///   @include delegate/example_delegate_functor.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param args the arguments to pass to the wrapped function
        ///
        /// <!-- inputs/outputs -->
        ///   @throw throws if the wrapped function throws
        ///
        void
        operator()(ARGS &&... args) const noexcept(false)
        {
            if (m_valid) {
                details::base_wrapper<void(ARGS...)> const *const ptr{
                    details::cast<details::base_wrapper<void(ARGS...)>>(&m_store)};

                ptr->call(bsl::forward<ARGS>(args)...);
            }
        }

        /// <!-- description -->
        ///   @brief If the bsl::delegate is valid, returns true, otherwise
        ///     returns false.
        ///   @include delegate/example_delegate_valid.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return If the bsl::delegate is valid, returns true, otherwise
        ///     returns false.
        ///
        [[nodiscard]] bool
        valid() const noexcept
        {
            return m_valid;
        }
    };

    /// @class bsl::delegate<void(ARGS...) noexcept>
    ///
    /// <!-- description -->
    ///   @brief Implements a simplified version of std::function. Unlike
    ///     std::function, a bsl::delegate has the following differences:
    ///     - Lambda functions, and binding in general are not supported.
    ///       Instead, either use a function pointer, or a member function
    ///       pointer. The reason is this implementation attempts to reduce
    ///       the overhead of std::function, and dynamic memory is not
    ///       supported, so the bsl::delegate has a fixed amount of memory
    ///       that it can support for wrapping.
    ///     - Operator bool is not supported as AUTOSAR does not allow for
    ///       the use of the conversion operator. Instead, use valid().
    ///     - Target access, non-member and helper functions are not supported.
    ///     - Functions marked as "noexcept" are supported. If the function
    ///       is marked as noexcept, the resulting bsl::delegate's functor
    ///       will also be marked as noexcept and vice versa.
    ///   @include example_delegate_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam ARGS The arguments to the delegate being wrapped
    ///
    template<typename... ARGS>
    class delegate<void(ARGS...) noexcept> final
    {
        /// @brief stores whether or not this delegate is valid
        bool m_valid;
        /// @brief stores the call wrapper
        aligned_storage_t<sizeof(void *) * 3> m_store;

    public:
        /// <!-- description -->
        ///   @brief Provides support for ensuring that a bsl::delegate is a
        ///     POD type, allowing it to be defined as a global resource.
        ///     When used globally, a bsl::delegate should not include {},
        ///     as required by AUTOSAR. The OS will automatically zero
        ///     initialize the bsl::delegate for you, marking the bsl::delegate
        ///     as invalid. If you use this constructor locally, you must
        ///     include {} to ensure the bsl::delegate is initialized, which
        ///     most compilers will warn about.
        ///   @include delegate/example_delegate_default_constructor.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        delegate() noexcept = default;

        /// <!-- description -->
        ///   @brief Creates a bsl::delegate from a function pointer. If the
        ///     function pointer is a nullptr, the resulting bsl::delegate
        ///     is marked as invalid, and will always return an error when
        ///     executed.
        ///   @include delegate/example_delegate_constructor_func.hpp
        ///
        ///   SUPPRESSION: PRQA 2180 - false positive
        ///   - We suppress this because A12-1-4 states that all constructors
        ///     that are callable from a fundamental type should be marked as
        ///     explicit. This is not a fundamental type and there for does
        ///     not apply.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param func a pointer to the delegate being wrapped
        ///
        delegate(void (*const func)(ARGS...) noexcept) noexcept    // PRQA S 2180 // NOLINT
            : m_valid{nullptr != func}, m_store{}
        {
            static_assert(sizeof(m_store) >= sizeof(details::func_wrapper<void(ARGS...)>));

            if (m_valid) {
                construct_at<details::func_wrapper<void(ARGS...) noexcept>>(&m_store, func);
            }
        }

        /// <!-- description -->
        ///   @brief Creates a bsl::delegate from a member function pointer. If
        ///     the function pointer is a nullptr, the resulting bsl::delegate
        ///     is marked as invalid, and will always return an error when
        ///     executed.
        ///   @include delegate/example_delegate_constructor_memfunc.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param t the object to execute the member function from
        ///   @param func a pointer to the delegate being wrapped
        ///
        template<typename T, typename U>
        delegate(T &t, void (U::*const func)(ARGS...) noexcept) noexcept    // --
            : m_valid{nullptr != func}, m_store{}
        {
            static_assert(sizeof(m_store) >= sizeof(details::memfunc_wrapper<T, void(ARGS...)>));

            if (m_valid) {
                construct_at<details::memfunc_wrapper<T, void(ARGS...) noexcept>>(
                    &m_store, t, func);
            }
        }

        /// <!-- description -->
        ///   @brief Creates a bsl::delegate from a const member function
        ///     pointer. If the function pointer is a nullptr, the resulting
        ///     bsl::delegate is marked as invalid, and will always return an
        ///     error when executed.
        ///   @include delegate/example_delegate_constructor_cmemfunc.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param t the object to execute the member function from
        ///   @param func a pointer to the delegate being wrapped
        ///
        template<typename T, typename U>
        delegate(T const &t, void (U::*const func)(ARGS...) const noexcept) noexcept    // --
            : m_valid{nullptr != func}, m_store{}
        {
            static_assert(sizeof(m_store) >= sizeof(details::cmemfunc_wrapper<T, void(ARGS...)>));

            if (m_valid) {
                construct_at<details::cmemfunc_wrapper<T, void(ARGS...) noexcept>>(
                    &m_store, t, func);
            }
        }

        /// <!-- description -->
        ///   @brief Execute the bsl::delegate by calling the wrapped function
        ///     with "args".
        ///   @include delegate/example_delegate_functor.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param args the arguments to pass to the wrapped function
        ///
        void
        operator()(ARGS &&... args) const noexcept
        {
            if (m_valid) {
                details::base_wrapper<void(ARGS...) noexcept> const *const ptr{
                    details::cast<details::base_wrapper<void(ARGS...) noexcept>>(&m_store)};

                ptr->call(bsl::forward<ARGS>(args)...);
            }
        }

        /// <!-- description -->
        ///   @brief If the bsl::delegate is valid, returns true, otherwise
        ///     returns false.
        ///   @include delegate/example_delegate_valid.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return If the bsl::delegate is valid, returns true, otherwise
        ///     returns false.
        ///
        [[nodiscard]] bool
        valid() const noexcept
        {
            return m_valid;
        }
    };

    /// @brief deduction guideline for bsl::delegate
    delegate()->delegate<void() noexcept>;

    /// @brief deduction guideline for bsl::delegate
    template<typename R, typename... ARGS>
    delegate(R (*)(ARGS...))->delegate<R(ARGS...)>;

    /// @brief deduction guideline for bsl::delegate
    template<typename T, typename U, typename R, typename... ARGS>
    delegate(T &t, R (U::*)(ARGS...))->delegate<R(ARGS...)>;

    /// @brief deduction guideline for bsl::delegate
    template<typename T, typename U, typename R, typename... ARGS>
    delegate(T const &t, R (U::*)(ARGS...) const)->delegate<R(ARGS...)>;

    /// @brief deduction guideline for bsl::delegate
    template<typename R, typename... ARGS>
    delegate(R (*)(ARGS...) noexcept)->delegate<R(ARGS...) noexcept>;

    /// @brief deduction guideline for bsl::delegate
    template<typename T, typename U, typename R, typename... ARGS>
    delegate(T &t, R (U::*)(ARGS...) noexcept)->delegate<R(ARGS...) noexcept>;

    /// @brief deduction guideline for bsl::delegate
    template<typename T, typename U, typename R, typename... ARGS>
    delegate(T const &t, R (U::*)(ARGS...) const noexcept)->delegate<R(ARGS...) noexcept>;

    /// @brief deduction guideline for bsl::delegate
    template<typename... ARGS>
    delegate(void (*)(ARGS...))->delegate<void(ARGS...)>;

    /// @brief deduction guideline for bsl::delegate
    template<typename T, typename U, typename... ARGS>
    delegate(T &t, void (U::*)(ARGS...))->delegate<void(ARGS...)>;

    /// @brief deduction guideline for bsl::delegate
    template<typename T, typename U, typename... ARGS>
    delegate(T const &t, void (U::*)(ARGS...) const)->delegate<void(ARGS...)>;

    /// @brief deduction guideline for bsl::delegate
    template<typename... ARGS>
    delegate(void (*)(ARGS...) noexcept)->delegate<void(ARGS...) noexcept>;

    /// @brief deduction guideline for bsl::delegate
    template<typename T, typename U, typename... ARGS>
    delegate(T &t, void (U::*)(ARGS...) noexcept)->delegate<void(ARGS...) noexcept>;

    /// @brief deduction guideline for bsl::delegate
    template<typename T, typename U, typename... ARGS>
    delegate(T const &t, void (U::*)(ARGS...) const noexcept)->delegate<void(ARGS...) noexcept>;

    /// @endcond doxygen on
}

#endif
