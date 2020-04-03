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
/// @file basic_errc_type.hpp
///

#ifndef BSL_BASIC_ERRC_TYPE_HPP
#define BSL_BASIC_ERRC_TYPE_HPP

#include "cstdint.hpp"
#include "cstr_type.hpp"
#include "discard.hpp"
#include "move.hpp"

namespace bsl
{
    /// @class bsl::basic_errc_type
    ///
    /// <!-- description -->
    ///   @brief Defines an error code. We do not use the same pattern as the
    ///     standard library. The goal is to ensure an error code can consume
    ///     a single register to ensure maximum compatibility with different
    ///     CPU archiectures that only have a 32bit return register. We also do
    ///     not use an enum to ensure custom error codes can be created. This
    ///     also means there are no error code categories. Instead, an error
    ///     code is checked if it is negative, and unchecked if it is positive
    ///     to align with AUTOSAR. Finally, we provide the ability to change
    ///     the type that an error code uses under the hood which allows you
    ///     to use a "long" type, or some other integer type depending on your
    ///     requirements (i.e., NTSTATUS).
    ///   @include example_basic_errc_type_overview.hpp
    ///
    template<typename T = bsl::int32, T SUCCESS = 0>
    class basic_errc_type final
    {
    public:
        /// @brief alias for: T
        using value_type = T;
        /// @brief alias for: T &
        using reference_type = T &;
        /// @brief alias for: T const &
        using const_reference_type = T const &;

        /// <!-- description -->
        ///   @brief Value initialization constructor
        ///   @include basic_errc_type/example_basic_errc_type_constructor_t.hpp
        ///
        ///   SUPPRESSION: PRQA 2180 - exception required
        ///   - We suppress this because A12-1-4 states that all constructors
        ///     that are callable from a fundamental type should be marked as
        ///     explicit. This is a fundamental type, but all implicit
        ///     conversions are disabled through the use of the implicit
        ///     general template constructor that is deleted which absorbs all
        ///     incoming potential implicit conversions.
        ///
        /// <!-- inputs/outputs -->
        ///   @param errc the error code to store
        ///
        constexpr basic_errc_type(    // PRQA S 2180 // NOLINT
            value_type const &errc = SUCCESS) noexcept
            : m_errc{errc}
        {}

        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::basic_errc_type
        ///
        ~basic_errc_type() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr basic_errc_type(basic_errc_type const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr basic_errc_type(basic_errc_type &&o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        constexpr basic_errc_type &operator=(basic_errc_type const &o) &noexcept = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        constexpr basic_errc_type &operator=(basic_errc_type &&o) &noexcept = default;

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
        /// <!-- inputs/outputs -->
        ///   @tparam O the type that could be implicitly converted
        ///   @param val the value that could be implicitly converted
        ///
        template<typename O>
        basic_errc_type(O val) noexcept = delete;    // PRQA S 2180

        /// <!-- description -->
        ///   @brief Returns the integer value that represents the error code.
        ///     Normally, this function should not be used, and instead, you
        ///     should use the other functions like ==, !=, operator bool(),
        ///     is_checked() and is_unchecked().
        ///   @include basic_errc_type/example_basic_errc_type_get.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the integer value that represents the error code.
        ///
        [[nodiscard]] constexpr const_reference_type
        get() const noexcept
        {
            return m_errc;
        }

        /// <!-- description -->
        ///   @brief Returns true if the error code contains SUCCESS,
        ///     otherwise, if the error code contains an error code,
        ///     returns false.
        ///   @include basic_errc_type/example_basic_errc_type_success.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the error code contains SUCCESS,
        ///     otherwise, if the error code contains an error code,
        ///     returns false.
        ///
        [[nodiscard]] constexpr bool
        success() const noexcept
        {
            return m_errc == SUCCESS;
        }

        /// <!-- description -->
        ///   @brief Returns true if the error code contains an error code,
        ///     otherwise, if the error code contains SUCCESS,
        ///     returns false.
        ///   @include basic_errc_type/example_basic_errc_type_failure.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the error code contains an error code,
        ///     otherwise, if the error code contains SUCCESS,
        ///     returns false.
        ///
        [[nodiscard]] constexpr bool
        failure() const noexcept
        {
            return m_errc != SUCCESS;
        }

        /// <!-- description -->
        ///   @brief Returns true if the error code is a checked error (i.e.,
        ///     that is the error code is negative), false otherwise. If this
        ///     error code is bsl::errc_success, returns false.
        ///   @include basic_errc_type/example_basic_errc_type_is_checked.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the error code is a checked error (i.e.,
        ///     that is the error code is negative), false otherwise. If this
        ///     error code is bsl::errc_success, returns false.
        ///
        [[nodiscard]] constexpr bool
        is_checked() const noexcept
        {
            return m_errc < 0;
        }

        /// <!-- description -->
        ///   @brief Returns true if the error code is an unchecked error
        ///     (i.e., that is the error code is positive), false otherwise.
        ///     If this error code is bsl::errc_success, returns false.
        ///   @include basic_errc_type/example_basic_errc_type_is_unchecked.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the error code is an unchecked error
        ///     (i.e., that is the error code is positive), false otherwise.
        ///     If this error code is bsl::errc_success, returns false.
        ///
        [[nodiscard]] constexpr bool
        is_unchecked() const noexcept
        {
            return m_errc > 0;
        }

        /// <!-- description -->
        ///   @brief Returns a human readable version of the error code. If
        ///     the error code is a custom, user defined error code, returns
        ///     a nullptr.
        ///   @include basic_errc_type/example_basic_errc_type_message.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a human readable version of the error code. If
        ///     the error code is a custom, user defined error code, returns
        ///     a nullptr.
        ///
        [[nodiscard]] constexpr cstr_type message() const noexcept;

    private:
        /// @brief stores the error code
        T m_errc;
    };

    /// <!-- description -->
    ///   @brief Returns true if the lhs is equal to the rhs, false otherwise
    ///   @include basic_errc_type/example_basic_errc_type_equals.hpp
    ///   @related bsl::basic_errc_type
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns true if the lhs is equal to the rhs, false otherwise
    ///
    template<typename T1, T1 SUCCESS1, typename T2, T2 SUCCESS2>
    constexpr bool
    operator==(
        basic_errc_type<T1, SUCCESS1> const &lhs, basic_errc_type<T2, SUCCESS2> const &rhs) noexcept
    {
        return lhs.get() == rhs.get();
    }

    /// <!-- description -->
    ///   @brief Returns false if the lhs is equal to the rhs, true otherwise
    ///   @include basic_errc_type/example_basic_errc_type_not_equals.hpp
    ///   @related bsl::basic_errc_type
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns false if the lhs is equal to the rhs, true otherwise
    ///
    template<typename T1, T1 SUCCESS1, typename T2, T2 SUCCESS2>
    constexpr bool
    operator!=(
        basic_errc_type<T1, SUCCESS1> const &lhs, basic_errc_type<T2, SUCCESS2> const &rhs) noexcept
    {
        return !(lhs == rhs);
    }
}

// -----------------------------------------------------------------------------
// Pre-defined Error Codes
// -----------------------------------------------------------------------------

namespace bsl
{
    /// @brief Defines the "no error" case
    constexpr basic_errc_type<> errc_success{0};
    /// @brief Defines the general unchecked error case
    constexpr basic_errc_type<> errc_failure{1};
    /// @brief Defines the general precondition error case
    constexpr basic_errc_type<> errc_precondition{2};
    /// @brief Defines the general postcondition error case
    constexpr basic_errc_type<> errc_postcondition{3};
    /// @brief Defines the general assertion error case
    constexpr basic_errc_type<> errc_assetion{4};

    /// @brief Defines an invalid argument error code
    constexpr basic_errc_type<> errc_invalid_argument{10};
    /// @brief Defines an out of bounds error code
    constexpr basic_errc_type<> errc_index_out_of_bounds{11};
    /// @brief Defines an out of bounds error code
    constexpr basic_errc_type<> errc_bad_function{12};

    /// @brief Defines an overflow, underflow or unsigned wrap error
    constexpr basic_errc_type<> errc_unsigned_wrap{30};
    /// @brief Defines an overflow, underflow or unsigned wrap error
    constexpr basic_errc_type<> errc_narrow_overflow{31};
    /// @brief Defines an overflow, underflow or unsigned wrap error
    constexpr basic_errc_type<> errc_signed_overflow{32};
    /// @brief Defines a divide by zero error
    constexpr basic_errc_type<> errc_divide_by_zero{33};
    /// @brief Defines an out of bounds error code
    constexpr basic_errc_type<> errc_nullptr_dereference{34};
}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace bsl
{
    /// <!-- description -->
    ///   @brief Returns a human readable version of the error code. If
    ///     the error code is a custom, user defined error code, returns
    ///     a nullptr.
    ///   @include basic_errc_type/example_basic_errc_type_message.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns a human readable version of the error code. If
    ///     the error code is a custom, user defined error code, returns
    ///     a nullptr.
    ///
    template<typename T, T SUCCESS>
    [[nodiscard]] constexpr cstr_type
    basic_errc_type<T, SUCCESS>::message() const noexcept
    {
        cstr_type msg{};

        switch (m_errc) {
            case errc_success.get(): {
                msg = "success";
                break;
            }

            case errc_failure.get(): {
                msg = "general failure";
                break;
            }

            case errc_precondition.get(): {
                msg = "general precondition failure";
                break;
            }

            case errc_postcondition.get(): {
                msg = "general postcondition failure";
                break;
            }

            case errc_assetion.get(): {
                msg = "general assertion failure";
                break;
            }

            case errc_invalid_argument.get(): {
                msg = "invalid argument (precondition) failure";
                break;
            }

            case errc_index_out_of_bounds.get(): {
                msg = "index out of bounds (precondition) failure";
                break;
            }

            case errc_bad_function.get(): {
                msg = "function not callable (precondition) failure";
                break;
            }

            case errc_unsigned_wrap.get(): {
                msg = "unsigned wrap (assertion) failure";
                break;
            }

            case errc_narrow_overflow.get(): {
                msg = "narrow overflow (assertion) failure";
                break;
            }

            case errc_signed_overflow.get(): {
                msg = "signed overflow (assertion) failure";
                break;
            }

            case errc_divide_by_zero.get(): {
                msg = "divide by zero (assertion) failure";
                break;
            }

            case errc_nullptr_dereference.get(): {
                msg = "null dereference (assertion) failure";
                break;
            }

            default: {
                break;
            }
        }

        return msg;
    }
}

#endif
