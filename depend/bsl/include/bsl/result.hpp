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
/// @file result.hpp
///

#ifndef BSL_RESULT_HPP
#define BSL_RESULT_HPP

#include "construct_at.hpp"
#include "cstdint.hpp"
#include "destroy_at.hpp"
#include "errc_type.hpp"
#include "in_place.hpp"
#include "move.hpp"
#include "source_location.hpp"
#include "swap.hpp"

#include "enable_if.hpp"
#include "is_same.hpp"
#include "is_move_constructible.hpp"
#include "is_nothrow_move_constructible.hpp"
#include "is_trivially_destructible.hpp"

namespace bsl
{
    namespace details
    {
        /// @enum bsl::details::result_type
        ///
        /// <!-- description -->
        ///   @brief Defines what a bsl::result is currently storing. This is
        ///     defined as a bsl::uint8 to ensure it is as small as possible.
        ///
        enum class result_type : bsl::uint8
        {
            contains_t,
            contains_e
        };
    }

    /// @class bsl::result
    ///
    /// <!-- description -->
    ///   @brief Provides the ability to return T or E from a function,
    ///     ensuring that T is only created if an error is not present.
    ///   @include example_result_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the nullable type
    ///   @tparam E the error type to use
    ///
    template<typename T, typename E = errc_type<>>
    class result final
    {
        static_assert(!is_same<T, E>::value);
        static_assert(!is_same<T, void>::value);
        static_assert(!is_move_constructible<T>::value || is_nothrow_move_constructible<T>::value);
        static_assert(!is_move_constructible<E>::value || is_nothrow_move_constructible<E>::value);
        static_assert(is_trivially_destructible<E>::value);

        /// <!-- description -->
        ///   @brief Swaps *this with other
        ///   @include result/exchange.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param lhs the left hand side of the exchange
        ///   @param rhs the right hand side of the exchange
        ///
        static constexpr void
        private_swap(result &lhs, result &rhs) noexcept
        {
            if (details::result_type::contains_t == lhs.m_which) {
                if (details::result_type::contains_t == rhs.m_which) {
                    bsl::swap(lhs.m_t, rhs.m_t);    // NOLINT
                }
                else {
                    E tmp_e{bsl::move(rhs.m_e)};                      // NOLINT
                    construct_at<T>(&rhs.m_t, bsl::move(lhs.m_t));    // NOLINT
                    destroy_at(&lhs.m_t);                             // NOLINT
                    construct_at<E>(&lhs.m_e, bsl::move(tmp_e));      // NOLINT
                }
            }
            else {
                if (details::result_type::contains_t == rhs.m_which) {
                    E tmp_e{bsl::move(lhs.m_e)};                      // NOLINT
                    construct_at<T>(&lhs.m_t, bsl::move(rhs.m_t));    // NOLINT
                    destroy_at(&rhs.m_t);                             // NOLINT
                    construct_at<E>(&rhs.m_e, bsl::move(tmp_e));      // NOLINT
                }
                else {
                    bsl::swap(lhs.m_e, rhs.m_e);    // NOLINT
                }
            }

            bsl::swap(lhs.m_which, rhs.m_which);
        }

    public:
        /// <!-- description -->
        ///   @brief Constructs a bsl::result that contains T,
        ///     by copying "t"
        ///   @include result/example_result_t_copy_constructor.hpp
        ///
        ///   SUPPRESSION: PRQA 2023 - exception required
        ///   - We suppress this because A13-3-1 states that you should not
        ///     overload functions that contain a forwarding reference because
        ///     it is confusing to the user. PRQA is detecting the presence of
        ///     the in place constructor. In this case, there is nothing
        ///     ambiguous about this situation as the user has to explicitly
        ///     state bsl::in_place, which disambiguated which constructor the
        ///     user is intending to use. It should be noted that objects like
        ///     std::pair, std::tuple and std::variant, which are all encouraged
        ///     by the spec have the same issue with this rule, so it is clear
        ///     it needs a better definition to ensure the library the spec
        ///     demands can actually be compliant with the spec itself.
        ///
        ///   SUPPRESSION: PRQA 2180 - exception required
        ///   - We suppress this because A12-1-4 states that all constructors
        ///     that are callable from a fundamental type should be marked as
        ///     explicit. This is a fundamental type, but all implicit
        ///     conversions are disabled through the use of the implicit
        ///     general template constructor that is deleted which absorbs all
        ///     incoming potential implicit conversions.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param t the value being copied
        ///
        /// <!-- exceptions -->
        ///   @throw throws if T's copy constructor throws
        ///
        constexpr result(T const &t) noexcept    // PRQA S 2023, 2180 // NOLINT
            : m_which{details::result_type::contains_t}, m_t{t}
        {}

        /// <!-- description -->
        ///   @brief Constructs a bsl::result that contains T,
        ///     by moving "t"
        ///   @include result/example_result_t_move_constructor.hpp
        ///
        ///   SUPPRESSION: PRQA 2023 - exception required
        ///   - We suppress this because A13-3-1 states that you should not
        ///     overload functions that contain a forwarding reference because
        ///     it is confusing to the user. PRQA is detecting the presence of
        ///     the in place constructor. In this case, there is nothing
        ///     ambiguous about this situation as the user has to explicitly
        ///     state bsl::in_place, which disambiguated which constructor the
        ///     user is intending to use. It should be noted that objects like
        ///     std::pair, std::tuple and std::variant, which are all encouraged
        ///     by the spec have the same issue with this rule, so it is clear
        ///     it needs a better definition to ensure the library the spec
        ///     demands can actually be compliant with the spec itself.
        ///
        ///   SUPPRESSION: PRQA 2180 - exception required
        ///   - We suppress this because A12-1-4 states that all constructors
        ///     that are callable from a fundamental type should be marked as
        ///     explicit. This is a fundamental type, but all implicit
        ///     conversions are disabled through the use of the implicit
        ///     general template constructor that is deleted which absorbs all
        ///     incoming potential implicit conversions.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param t the value being moved
        ///
        /// <!-- exceptions -->
        ///   @throw throws if T's copy constructor throws
        ///
        constexpr result(T &&t) noexcept    // PRQA S 2023, 2180 // NOLINT
            : m_which{details::result_type::contains_t}, m_t{bsl::move(t)}
        {}

        /// <!-- description -->
        ///   @brief Constructs a bsl::result that contains T by constructing
        ///     T in place.
        ///   @include result/example_result_t_in_place_constructor.hpp
        ///
        ///   SUPPRESSION: PRQA 2023 - exception required
        ///   - We suppress this because A13-3-1 states that you should not
        ///     overload functions that contain a forwarding reference because
        ///     it is confusing to the user. PRQA is detecting the presence of
        ///     the in place constructor. In this case, there is nothing
        ///     ambiguous about this situation as the user has to explicitly
        ///     state bsl::in_place, which disambiguated which constructor the
        ///     user is intending to use. It should be noted that objects like
        ///     std::pair, std::tuple and std::variant, which are all encouraged
        ///     by the spec have the same issue with this rule, so it is clear
        ///     it needs a better definition to ensure the library the spec
        ///     demands can actually be compliant with the spec itself.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param ip provide bsl::in_place to construct in place
        ///   @param args the arguments to create T with
        ///
        /// <!-- exceptions -->
        ///   @throw throws if T's constructor throws
        ///
        template<typename... ARGS>
        constexpr result(    // PRQA S 2023 // NOLINT
            bsl::in_place_t const &ip,
            ARGS &&... args) noexcept
            : m_which{details::result_type::contains_t}, m_t{bsl::forward<ARGS>(args)...}
        {
            bsl::discard(ip);
        }

        /// <!-- description -->
        ///   @brief Constructs a bsl::result that contains E,
        ///     by copying "e"
        ///   @include result/example_result_errc_copy_constructor.hpp
        ///
        ///   SUPPRESSION: PRQA 2023 - exception required
        ///   - We suppress this because A13-3-1 states that you should not
        ///     overload functions that contain a forwarding reference because
        ///     it is confusing to the user. PRQA is detecting the presence of
        ///     the in place constructor. In this case, there is nothing
        ///     ambiguous about this situation as the user has to explicitly
        ///     state bsl::in_place, which disambiguated which constructor the
        ///     user is intending to use. It should be noted that objects like
        ///     std::pair, std::tuple and std::variant, which are all encouraged
        ///     by the spec have the same issue with this rule, so it is clear
        ///     it needs a better definition to ensure the library the spec
        ///     demands can actually be compliant with the spec itself.
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
        ///   @param e the error code being copied
        ///   @param sloc the source location of the error
        ///
        /// <!-- exceptions -->
        ///   @throw throws if E's copy constructor throws
        ///
        constexpr result(    // PRQA S 2023, 2180 // NOLINT
            E const &e,
            sloc_type const &sloc = here()) noexcept
            : m_which{details::result_type::contains_e}, m_e{e}
        {
            bsl::discard(sloc);
        }

        /// <!-- description -->
        ///   @brief Constructs a bsl::result that contains E,
        ///     by moving "e"
        ///   @include result/example_result_errc_move_constructor.hpp
        ///
        ///   SUPPRESSION: PRQA 2023 - exception required
        ///   - We suppress this because A13-3-1 states that you should not
        ///     overload functions that contain a forwarding reference because
        ///     it is confusing to the user. PRQA is detecting the presence of
        ///     the in place constructor. In this case, there is nothing
        ///     ambiguous about this situation as the user has to explicitly
        ///     state bsl::in_place, which disambiguated which constructor the
        ///     user is intending to use. It should be noted that objects like
        ///     std::pair, std::tuple and std::variant, which are all encouraged
        ///     by the spec have the same issue with this rule, so it is clear
        ///     it needs a better definition to ensure the library the spec
        ///     demands can actually be compliant with the spec itself.
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
        ///   @param e the error code being moved
        ///   @param sloc the source location of the error
        ///
        /// <!-- exceptions -->
        ///   @throw throws if E's copy constructor throws
        ///
        constexpr result(    // PRQA S 2023, 2180 // NOLINT
            E &&e,
            sloc_type const &sloc = here()) noexcept
            : m_which{details::result_type::contains_e}, m_e{bsl::move(e)}
        {
            bsl::discard(sloc);
        }

        /// <!-- description -->
        ///   @brief copy constructor
        ///   @include result/example_result_copy_constructor.hpp
        ///
        ///   SUPPRESSION: PRQA 4285 - false positive
        ///   - We suppress this because A12-8-1 states a copy/move should
        ///     not have a side effect other than the copy/move itself.
        ///     This is a false positive because there are not side effects
        ///     in this code below. PRQA is not properly handling
        ///     the union as allowed by AUTOSAR.
        ///
        ///   SUPPRESSION: PRQA 2023 - exception required
        ///   - We suppress this because A13-3-1 states that you should not
        ///     overload functions that contain a forwarding reference because
        ///     it is confusing to the user. PRQA is detecting the presence of
        ///     the in place constructor. In this case, there is nothing
        ///     ambiguous about this situation as the user has to explicitly
        ///     state bsl::in_place, which disambiguated which constructor the
        ///     user is intending to use. It should be noted that objects like
        ///     std::pair, std::tuple and std::variant, which are all encouraged
        ///     by the spec have the same issue with this rule, so it is clear
        ///     it needs a better definition to ensure the library the spec
        ///     demands can actually be compliant with the spec itself.
        ///
        ///   SUPPRESSION: PRQA 4050 - false positive
        ///   - We suppress this because A12-1-1 states that all member
        ///     variables should be explicitly initialized. It does not
        ///     state that they must be in the initializer list.
        ///     Furthermore, it is impossible to initialize union members
        ///     in an initializer list in a copy/move constructor, which
        ///     PRQA should be capable of detecting, and it doesn't.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        /// <!-- exceptions -->
        ///   @throw throws if T or E's copy constructor throws
        ///
        constexpr result(result const &o) noexcept(false)    // PRQA S 4285, 2023
            : m_which{o.m_which}                             // PRQA S 4050
        {
            if (details::result_type::contains_t == m_which) {
                construct_at<T>(&m_t, o.m_t);    // NOLINT
            }
            else {
                construct_at<E>(&m_e, o.m_e);    // NOLINT
            }
        }

        /// <!-- description -->
        ///   @brief move constructor
        ///   @include result/example_result_move_constructor.hpp
        ///
        ///   SUPPRESSION: PRQA 4285 - false positive
        ///   - We suppress this because A12-8-1 states a copy/move should
        ///     not have a side effect other than the copy/move itself.
        ///     This is a false positive because the only side effect is
        ///     the copy/move as required. PRQA is not properly handling
        ///     the union as allows by AUTOSAR.
        ///
        ///   SUPPRESSION: PRQA 2023 - exception required
        ///   - We suppress this because A13-3-1 states that you should not
        ///     overload functions that contain a forwarding reference because
        ///     it is confusing to the user. PRQA is detecting the presence of
        ///     the in place constructor. In this case, there is nothing
        ///     ambiguous about this situation as the user has to explicitly
        ///     state bsl::in_place, which disambiguated which constructor the
        ///     user is intending to use. It should be noted that objects like
        ///     std::pair, std::tuple and std::variant, which are all encouraged
        ///     by the spec have the same issue with this rule, so it is clear
        ///     it needs a better definition to ensure the library the spec
        ///     demands can actually be compliant with the spec itself.
        ///
        ///   SUPPRESSION: PRQA 4050 - false positive
        ///   - We suppress this because A12-1-1 states that all member
        ///     variables should be explicitly initialized. It does not
        ///     state that they must be in the initializer list.
        ///     Furthermore, it is impossible to initialize union members
        ///     in an initializer list in a copy/move constructor, which
        ///     PRQA should be capable of detecting, and it doesn't.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr result(result &&o) noexcept    // PRQA S 4285, 2023
            : m_which{o.m_which}                 // PRQA S 4050
        {
            if (details::result_type::contains_t == m_which) {
                construct_at<T>(&m_t, bsl::move(o.m_t));    // NOLINT
            }
            else {
                construct_at<E>(&m_e, bsl::move(o.m_e));    // NOLINT
            }
        }

        /// <!-- description -->
        ///   @brief This constructor allows for single argument constructors
        ///     without the need to mark them as explicit as it will absorb
        ///     any incoming potential implicit conversion and prevent it.
        ///
        ///   SUPPRESSION: PRQA 2180 - false positive
        ///   - We suppress this because A12-1-4 states that all constructors
        ///     that are callable from a fundamental type should be marked as
        ///     explicit. This is callable with a fundamental type, but it
        ///     is marked as "delete" which means it does not apply.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam O the type that could be implicitly converted
        ///   @param val the value that could be implicitly converted
        ///
        template<typename O>
        result(O val) noexcept = delete;    // PRQA S 2180

        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::result. Since
        ///     we require E to be trivially destructible, we only need to
        ///     call a destructor if this object contains a T
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        ~result() noexcept
        {
            if (details::result_type::contains_t == m_which) {
                destroy_at(&m_t);    // NOLINT
            }
        }

        /// <!-- description -->
        ///   @brief copy assignment
        ///   @include result/example_result_copy_assignment.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        /// <!-- exceptions -->
        ///   @throw throws if T or E's copy constructor throws
        ///
        [[maybe_unused]] constexpr result &
            operator=(result const &o) &
            noexcept(false)
        {
            result tmp{o};
            private_swap(*this, tmp);
            return *this;
        }

        /// <!-- description -->
        ///   @brief move assignment
        ///   @include result/example_result_move_assignment.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr result &
            operator=(result &&o) &
            noexcept
        {
            result tmp{bsl::move(o)};
            private_swap(*this, tmp);
            return *this;
        }

        /// <!-- description -->
        ///   @brief Returns a handle to T if this object contains T,
        ///     otherwise it returns a nullptr.
        ///   @include result/example_result_get_if.hpp
        ///
        ///   SUPPRESSION: PRQA 4024 - false positive - non-automated
        ///   - We suppress this because A9-3-1 states that a class should
        ///     not return a non-const handle to an object. AUTOSAR
        ///     provides an exception for classes that mimic a smart
        ///     pointer or a container, which is what this class is doing.
        ///     It should be noted that such exceptions are likely not
        ///     detectable by PRQA, and thus, this suppression will likely
        ///     always be required.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a handle to T if this object contains T,
        ///     otherwise it returns a nullptr.
        ///
        [[nodiscard]] constexpr T *
            get_if() &
            noexcept
        {
            if (details::result_type::contains_t == m_which) {
                return &m_t;    // PRQA S 4024 // NOLINT
            }

            return nullptr;
        }

        /// <!-- description -->
        ///   @brief Prevents the use of get_if() on temporary objects, which
        ///     would result in UB.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a handle to T if this object contains T,
        ///     otherwise it returns a nullptr.
        ///
        [[nodiscard]] constexpr T *get_if() &&noexcept = delete;

        /// <!-- description -->
        ///   @brief Returns a handle to T if this object contains T,
        ///     otherwise it returns a nullptr.
        ///   @include result/example_result_get_if.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a handle to T if this object contains T,
        ///     otherwise it returns a nullptr.
        ///
        [[nodiscard]] constexpr T const *
        get_if() const &noexcept
        {
            if (details::result_type::contains_t == m_which) {
                return &m_t;    // NOLINT
            }

            return nullptr;
        }

        /// <!-- description -->
        ///   @brief Prevents the use of get_if() on temporary objects, which
        ///     would result in UB.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a handle to T if this object contains T,
        ///     otherwise it returns a nullptr.
        ///
        [[nodiscard]] constexpr T const *get_if() const &&noexcept = delete;

        /// <!-- description -->
        ///   @brief Returns an error code if this object contains E,
        ///     otherwise it returns "fallback".
        ///   @include result/example_result_errc.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param fallback returned if this bsl::result contains T
        ///   @return Returns an error code if this object contains E,
        ///     otherwise it returns "or".
        ///
        [[nodiscard]] constexpr E
        errc(E const &fallback = E{}) const noexcept
        {
            if (details::result_type::contains_e == m_which) {
                return m_e;    // NOLINT
            }

            return fallback;
        }

        /// <!-- description -->
        ///   @brief Returns true if the bsl::result contains T,
        ///     otherwise, if the bsl::result contains an error code,
        ///     returns false.
        ///   @include result/example_result_success.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the bsl::result contains T,
        ///     otherwise, if the bsl::result contains an error code,
        ///     returns false.
        ///
        [[nodiscard]] constexpr bool
        success() const noexcept
        {
            return details::result_type::contains_t == m_which;
        }

        /// <!-- description -->
        ///   @brief Returns true if the bsl::result contains E,
        ///     otherwise, if the bsl::result contains T,
        ///     returns false.
        ///   @include result/example_result_failure.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the bsl::result contains E,
        ///     otherwise, if the bsl::result contains T,
        ///     returns false.
        ///
        [[nodiscard]] constexpr bool
        failure() const noexcept
        {
            return details::result_type::contains_e == m_which;
        }

    private:
        /// @brief stores which type the union stores
        details::result_type m_which;

        /// @brief Provides access to T or an error code
        ///
        ///   SUPPRESSION: PRQA 2176 - false positive
        ///   - We suppress this because A9-5-1 states that unions are
        ///     not allowed with the exception of tagged unions. In this
        ///     case, we have implemented a tagged union. We tried to keep
        ///     the implementation as close to the example in the spec as
        ///     possible, and PRQA is still not able to detect this.
        ///
        ///   SUPPRESSION: PRQA 2176 - false positive
        ///   - We suppress this because A2-7-3 states that all class members
        ///     should be documented. This is clearly documented.
        ///
        union    // PRQA S 2176, 2026, 2177
        {
            /// @brief stores T when not storing an error code
            T m_t;
            /// @brief stores an error code when not storing T
            E m_e;
        };
    };

    /// <!-- description -->
    ///   @brief Returns true if the lhs is equal to the rhs, false otherwise
    ///   @include result/example_result_equals.hpp
    ///   @related bsl::result
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns true if the lhs is equal to the rhs, false otherwise
    ///
    template<typename T, typename E>
    constexpr bool
    operator==(result<T, E> const &lhs, result<T, E> const &rhs) noexcept
    {
        if (lhs.success() != rhs.success()) {
            return false;
        }

        if (lhs.success()) {
            return *lhs.get_if() == *rhs.get_if();
        }

        return lhs.errc() == rhs.errc();
    }

    /// <!-- description -->
    ///   @brief Returns false if the lhs is equal to the rhs, true otherwise
    ///   @include result/example_result_not_equals.hpp
    ///   @related bsl::result
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns false if the lhs is equal to the rhs, true otherwise
    ///
    template<typename T, typename E>
    constexpr bool
    operator!=(result<T, E> const &lhs, result<T, E> const &rhs) noexcept
    {
        return !(lhs == rhs);
    }
}

#endif
