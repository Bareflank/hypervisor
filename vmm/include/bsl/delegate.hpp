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
///
/// @file delegate.hpp
///

#ifndef BSL_DELEGATE_HPP
#define BSL_DELEGATE_HPP

#include "aligned_storage.hpp"
#include "conditional.hpp"
#include "cstdint.hpp"
#include "is_void.hpp"
#include "result.hpp"

namespace bsl
{
    /// @cond doxygen off

    template<typename F>
    class delegate;

    /// @endcond doxygen on

    namespace details
    {
        /// <!-- description -->
        ///   @brief Converts a heap to a function.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam FUNC the function type to convert the heap to
        ///   @param heap the heap to convert to FUNC
        ///   @return A pointer to heap, as a FUNC
        ///
        template<typename FUNC>
        [[nodiscard]] static constexpr FUNC const &
        get_func(void const *const heap) noexcept
        {
            return *static_cast<FUNC const *>(heap);
        }

        /// <!-- description -->
        ///   @brief The type erased version of the wrapped function given
        ///     a pointer to the heap that is actually storing the wrapped
        ///     function. This is the indirection that the delegate calls
        ///     when calling the wrapped function. Remember the whole point
        ///     of a delegate is to be able to call either a function or a
        ///     member function pointer, without knowing which version it
        ///     has. The heap stores the function/member function pointer
        ///     information. Since this function's signature does not include
        ///     FUNC (only a void * and ARGS), a pointer to this function
        ///     can be stored and called by the delegate. All this function
        ///     has to do is convert the provided heap to FUNC and call it.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam FUNC the function type to move
        ///   @tparam R the return value of the function
        ///   @tparam ARGS the argument to pass to the function
        ///   @param heap the memory containing the wrapped function.
        ///   @param args the arguments to pass to the wrapped function.
        ///   @return Returns the result of executing the wrapped function.
        ///
        template<typename FUNC, typename R, typename... ARGS>
        [[maybe_unused]] constexpr R
        call_func_generic(void const *const heap, ARGS &&... args) noexcept(false)
        {
            return get_func<FUNC>(heap)(bsl::forward<ARGS>(args)...);
        }

    }

    /// @brief the total size of the heap
    constexpr bsl::uintmax delegate_heap_size{16};
    /// @brief the alignment of the heap
    constexpr bsl::uintmax delegate_heap_align{32};

    /// <!-- description -->
    ///   @brief A bsl::delegate is similar to a std::function with some
    ///     key differences:
    ///     - Like other fast delegate types, and unlike the std::function,
    ///       a bsl::delegate can automatically bind to a member function
    ///       pointer (i.e., no need for a lambda or std::bind). This ensures
    ///       the internal implementation is better optimized, and removes
    ///       issues with AUTOSAR compliance.
    ///     - Lambda functions are not supported. If you need support for
    ///       lambda functions, implement your own functor type and use the
    ///       member function pointer syntax. We do not support lambdas as
    ///       they require dynamic memory. Creating your own functor type
    ///       ensures you are managing memory yourself properly.
    ///     - We provide the empty() function to determine if the delegate
    ///       has been properly initialized.
    ///     - For functions that return a value, we return bsl::result<R>
    ///       instead of R and throwing if the delegate is empty().
    ///     - We support noexcept. That is, if you wrap a function marked as
    ///       noexcept, the delegate is also noexcept.
    ///   @include example_delegate_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam R the return value of the delegate
    ///   @tparam ARGS the argument to pass to the delegate
    ///
    template<typename R, typename... ARGS>
    class delegate<R(ARGS...)>    // NOLINT
    {
        /// @brief defines the type used to store the wrapped function
        using heap_type = aligned_storage_t<delegate_heap_size, delegate_heap_align>;
        /// @brief defines the type of function to call when op() is called
        using call_type = R (*)(void const *const, ARGS &&...);

        /// @brief stores the wrapped function
        heap_type m_heap;
        /// @brief stores the function to call when op() is called.
        call_type m_call;

    public:
        /// @brief the return type of the wrapped function.
        using result_type = R;

        /// <!-- description -->
        ///   @brief Default constructor that creates a delegate with
        ///     m_heap and m_call set to 0. Note that like other types
        ///     in the BSL, the bsl::delegate is a POD type. This
        ///     means that when declaring a global, default constructed
        ///     bsl::delegate, DO NOT include the {} for
        ///     initialization. Instead, remove the {} and the global
        ///     bsl::delegate will be included in the BSS section of
        ///     the executable, and initialized to 0 for you. All other
        ///     instantiations of a bsl::delegate (or any POD
        ///     type), should be initialized using {} to ensure the POD is
        ///     properly initialized. Using the above method for global
        ///     initialization ensures that global constructors are not
        ///     executed at runtime, which is required by AUTOSAR.
        ///   @include delegate/example_delegate_default_constructor.hpp
        ///
        constexpr delegate() noexcept = default;

        /// <!-- description -->
        ///   @brief Creates a bsl::delegate that wraps a function pointer.
        ///   @include delegate/example_delegate_fp_constructor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param func a pointer to the function to wrap
        ///
        constexpr delegate(R (*func)(ARGS...)) noexcept    // NOLINT
            : m_heap{}, m_call{}
        {
            if (nullptr != func) {
                m_call = &details::call_func_generic<decltype(func), R, ARGS...>;
                bsl::construct_at<decltype(func)>(&m_heap, func);
            }
        }

        /// <!-- description -->
        ///   @brief Creates a bsl::delegate that wraps a member function
        ///     pointer.
        ///   @include delegate/example_delegate_mfp_constructor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param t a pointer to the object that owns "mfp"
        ///   @param mfp a pointer to the member function to wrap
        ///
        template<typename T, typename U>
        constexpr delegate(T *t, R (U::*mfp)(ARGS...)) noexcept    // --
            : m_heap{}, m_call{}
        {
            if (nullptr != t && nullptr != mfp) {
                auto func = [mfp, t](ARGS &&... args) -> R {
                    return (t->*mfp)(bsl::forward<ARGS>(args)...);
                };

                static_assert(sizeof(func) <= sizeof(heap_type));

                m_call = &details::call_func_generic<decltype(func), R, ARGS...>;
                bsl::construct_at<decltype(func)>(&m_heap, func);
            }
        }

        /// <!-- description -->
        ///   @brief Creates a bsl::delegate that wraps a const member
        ///     function pointer.
        ///   @include delegate/example_delegate_cmfp_constructor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param t a pointer to the object that owns "mfp"
        ///   @param mfp a pointer to the member function to wrap
        ///
        template<typename T, typename U>
        constexpr delegate(T *t, R (U::*mfp)(ARGS...) const) noexcept    // --
            : m_heap{}, m_call{}
        {
            if (nullptr != t && nullptr != mfp) {
                auto func = [mfp, t](ARGS &&... args) -> R {
                    return (t->*mfp)(bsl::forward<ARGS>(args)...);
                };

                static_assert(sizeof(func) <= sizeof(heap_type));

                m_call = &details::call_func_generic<decltype(func), R, ARGS...>;
                bsl::construct_at<decltype(func)>(&m_heap, func);
            }
        }

        /// <!-- description -->
        ///   @brief Calls the wrapped function with "ARGS". If the wrapped
        ///     function returns a value, the value is returned as a
        ///     bsl::result<R>. If the provided delegate is empty(), the
        ///     bsl::result<R> will return a bsl::errc_bad_function. If the
        ///     wrapped function returns void, this function returns a
        ///     bsl::errc_type, returning bsl::errc_bad_function if the
        ///     delegate is empty(), bsl::errc_success otherwise.
        ///   @include delegate/example_delegate_functor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param args the arguments to pass to the wrapped function.
        ///   @return If the wrapped function returns a value, the value is
        ///     returned as a bsl::result<R>. If the provided delegate is
        ///     empty(), the bsl::result<R> will return a
        ///     bsl::errc_bad_function. If the wrapped function returns void,
        ///     this function returns a bsl::errc_type, returning
        ///     bsl::errc_bad_function if the delegate is empty(),
        ///     bsl::errc_success otherwise.
        ///
        [[maybe_unused]] constexpr conditional_t<is_void<R>::value, bsl::errc_type, result<R>>
        operator()(ARGS... args) const
        {
            if constexpr (is_void<R>::value) {
                if (!this->empty()) {
                    m_call(&m_heap, bsl::forward<ARGS>(args)...);
                    return {bsl::errc_success};
                }
            }
            else {
                if (!this->empty()) {
                    return {bsl::in_place, m_call(&m_heap, bsl::forward<ARGS>(args)...)};
                }
            }

            return {bsl::errc_bad_function};
        }

        /// <!-- description -->
        ///   @brief Returns true if the delegate was constructed using the
        ///     default constructor, or if a nullptr was provided during
        ///     construction (for either the object or function pointer
        ///     parameters).
        ///   @include delegate/example_delegate_empty.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the delegate was constructed using the
        ///     default constructor, or if a nullptr was provided during
        ///     construction (for either the object or function pointer
        ///     parameters).
        ///
        [[nodiscard]] constexpr bool
        empty() const noexcept
        {
            return nullptr == m_call;
        }
    };

    /// @cond doxygen off

    /// <!-- description -->
    ///   @brief A bsl::delegate is similar to a std::function with some
    ///     key differences:
    ///     - Like other fast delegate types, and unlike the std::function,
    ///       a bsl::delegate can automatically bind to a member function
    ///       pointer (i.e., no need for a lambda or std::bind). This ensures
    ///       the internal implementation is better optimized, and removes
    ///       issues with AUTOSAR compliance.
    ///     - Lambda functions are not supported. If you need support for
    ///       lambda functions, implement your own functor type and use the
    ///       member function pointer syntax. We do not support lambdas as
    ///       they require dynamic memory. Creating your own functor type
    ///       ensures you are managing memory yourself properly.
    ///     - We provide the empty() function to determine if the delegate
    ///       has been properly initialized.
    ///     - For functions that return a value, we return bsl::result<R>
    ///       instead of R and throwing if the delegate is empty().
    ///     - We support noexcept. That is, if you wrap a function marked as
    ///       noexcept, the delegate is also noexcept.
    ///   @include example_delegate_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam R the return value of the delegate
    ///   @tparam ARGS the argument to pass to the delegate
    ///
    template<typename R, typename... ARGS>
    class delegate<R(ARGS...) noexcept>    // NOLINT
    {
        /// @brief defines the type used to store the wrapped function
        using heap_type = aligned_storage_t<delegate_heap_size, delegate_heap_align>;
        /// @brief defines the type of function to call when op() is called
        using call_type = R (*)(void const *const, ARGS &&...);

        /// @brief stores the wrapped function
        heap_type m_heap;
        /// @brief stores the function to call when op() is called.
        call_type m_call;

    public:
        /// @brief the return type of the wrapped function.
        using result_type = R;

        /// <!-- description -->
        ///   @brief Default constructor that creates a delegate with
        ///     m_heap and m_call set to 0. Note that like other types
        ///     in the BSL, the bsl::delegate is a POD type. This
        ///     means that when declaring a global, default constructed
        ///     bsl::delegate, DO NOT include the {} for
        ///     initialization. Instead, remove the {} and the global
        ///     bsl::delegate will be included in the BSS section of
        ///     the executable, and initialized to 0 for you. All other
        ///     instantiations of a bsl::delegate (or any POD
        ///     type), should be initialized using {} to ensure the POD is
        ///     properly initialized. Using the above method for global
        ///     initialization ensures that global constructors are not
        ///     executed at runtime, which is required by AUTOSAR.
        ///   @include delegate/example_delegate_default_constructor.hpp
        ///
        constexpr delegate() noexcept = default;

        /// <!-- description -->
        ///   @brief Creates a bsl::delegate that wraps a function pointer.
        ///   @include delegate/example_delegate_fp_constructor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param func a pointer to the function to wrap
        ///
        constexpr delegate(R (*func)(ARGS...) noexcept) noexcept    // NOLINT
            : m_heap{}, m_call{}
        {
            if (nullptr != func) {
                m_call = &details::call_func_generic<decltype(func), R, ARGS...>;
                bsl::construct_at<decltype(func)>(&m_heap, func);
            }
        }

        /// <!-- description -->
        ///   @brief Creates a bsl::delegate that wraps a member function
        ///     pointer.
        ///   @include delegate/example_delegate_mfp_constructor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param t a pointer to the object that owns "mfp"
        ///   @param mfp a pointer to the member function to wrap
        ///
        template<typename T, typename U>
        constexpr delegate(T *t, R (U::*mfp)(ARGS...) noexcept) noexcept    // --
            : m_heap{}, m_call{}
        {
            if (nullptr != t && nullptr != mfp) {
                auto func = [mfp, t](ARGS &&... args) noexcept -> R {
                    return (t->*mfp)(bsl::forward<ARGS>(args)...);
                };

                static_assert(sizeof(func) <= sizeof(heap_type));

                m_call = &details::call_func_generic<decltype(func), R, ARGS...>;
                bsl::construct_at<decltype(func)>(&m_heap, func);
            }
        }

        /// <!-- description -->
        ///   @brief Creates a bsl::delegate that wraps a const member
        ///     function pointer.
        ///   @include delegate/example_delegate_cmfp_constructor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param t a pointer to the object that owns "mfp"
        ///   @param mfp a pointer to the member function to wrap
        ///
        template<typename T, typename U>
        constexpr delegate(T *t, R (U::*mfp)(ARGS...) const noexcept) noexcept    // --
            : m_heap{}, m_call{}
        {
            if (nullptr != t && nullptr != mfp) {
                auto func = [mfp, t](ARGS &&... args) noexcept -> R {
                    return (t->*mfp)(bsl::forward<ARGS>(args)...);
                };

                static_assert(sizeof(func) <= sizeof(heap_type));

                m_call = &details::call_func_generic<decltype(func), R, ARGS...>;
                bsl::construct_at<decltype(func)>(&m_heap, func);
            }
        }

        /// <!-- description -->
        ///   @brief Calls the wrapped function with "ARGS". If the wrapped
        ///     function returns a value, the value is returned as a
        ///     bsl::result<R>. If the provided delegate is empty(), the
        ///     bsl::result<R> will return a bsl::errc_bad_function. If the
        ///     wrapped function returns void, this function returns a
        ///     bsl::errc_type, returning bsl::errc_bad_function if the
        ///     delegate is empty(), bsl::errc_success otherwise.
        ///   @include delegate/example_delegate_functor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param args the arguments to pass to the wrapped function.
        ///   @return If the wrapped function returns a value, the value is
        ///     returned as a bsl::result<R>. If the provided delegate is
        ///     empty(), the bsl::result<R> will return a
        ///     bsl::errc_bad_function. If the wrapped function returns void,
        ///     this function returns a bsl::errc_type, returning
        ///     bsl::errc_bad_function if the delegate is empty(),
        ///     bsl::errc_success otherwise.
        ///
        [[maybe_unused]] constexpr conditional_t<is_void<R>::value, bsl::errc_type, result<R>>
        operator()(ARGS... args) const noexcept
        {
            if constexpr (is_void<R>::value) {
                if (!this->empty()) {
                    m_call(&m_heap, bsl::forward<ARGS>(args)...);
                    return {bsl::errc_success};
                }
            }
            else {
                if (!this->empty()) {
                    return {bsl::in_place, m_call(&m_heap, bsl::forward<ARGS>(args)...)};
                }
            }

            return {bsl::errc_bad_function};
        }

        /// <!-- description -->
        ///   @brief Returns true if the delegate was constructed using the
        ///     default constructor, or if a nullptr was provided during
        ///     construction (for either the object or function pointer
        ///     parameters).
        ///   @include delegate/example_delegate_empty.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the delegate was constructed using the
        ///     default constructor, or if a nullptr was provided during
        ///     construction (for either the object or function pointer
        ///     parameters).
        ///
        [[nodiscard]] constexpr bool
        empty() const noexcept
        {
            return nullptr == m_call;
        }
    };

    /// @brief deduction guideline for bsl::delegate
    delegate()->delegate<void() noexcept>;

    /// @brief deduction guideline for bsl::delegate
    template<typename R, typename... ARGS>
    explicit delegate(R (*)(ARGS...)) -> delegate<R(ARGS...)>;

    /// @brief deduction guideline for bsl::delegate
    template<typename T, typename U, typename R, typename... ARGS>
    delegate(T *t, R (U::*)(ARGS...)) -> delegate<R(ARGS...)>;

    /// @brief deduction guideline for bsl::delegate
    template<typename T, typename U, typename R, typename... ARGS>
    delegate(T *t, R (U::*)(ARGS...) const) -> delegate<R(ARGS...)>;

    /// @brief deduction guideline for bsl::delegate
    template<typename R, typename... ARGS>
    explicit delegate(R (*)(ARGS...) noexcept) -> delegate<R(ARGS...) noexcept>;

    /// @brief deduction guideline for bsl::delegate
    template<typename T, typename U, typename R, typename... ARGS>
    delegate(T *t, R (U::*)(ARGS...) noexcept) -> delegate<R(ARGS...) noexcept>;

    /// @brief deduction guideline for bsl::delegate
    template<typename T, typename U, typename R, typename... ARGS>
    delegate(T *t, R (U::*)(ARGS...) const noexcept) -> delegate<R(ARGS...) noexcept>;

    /// @endcond doxygen off
}

#endif
