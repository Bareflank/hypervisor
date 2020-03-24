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

#ifndef BSL_NUMERIC_LIMITS_HPP
#define BSL_NUMERIC_LIMITS_HPP

#include "climits.hpp"
#include "cstdint.hpp"
#include "float_denorm_style.hpp"
#include "float_round_style.hpp"

namespace bsl
{
    /// @class bsl::numeric_limits
    ///
    /// <!-- description -->
    ///   @brief Implements std::numeric_limits
    ///   @include example_numeric_limits_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type to get information about
    ///
    template<typename T>
    struct numeric_limits final
    {
        /// @brief stores whether or not this is a specialization
        static constexpr bool is_specialized{false};
        /// @brief stores whether or not T is signed
        static constexpr bool is_signed{false};
        /// @brief stores whether or not T is an integer
        static constexpr bool is_integer{false};
        /// @brief stores whether or not T is exact
        static constexpr bool is_exact{false};
        /// @brief stores whether or not T has defined infinity
        static constexpr bool has_infinity{false};
        /// @brief stores whether or not T has a quiet NaN
        static constexpr bool has_quiet_NaN{false};
        /// @brief stores whether or not T has a signaling NaN
        static constexpr bool has_signaling_NaN{false};
        /// @brief stores the denorm style of T
        static constexpr float_denorm_style has_denorm{float_denorm_style::denorm_absent};
        /// @brief stores whether or not floating points detect loss
        static constexpr bool has_denorm_loss{false};
        /// @brief stores the rounding style of T
        static constexpr float_round_style round_style{float_round_style::round_toward_zero};
        /// @brief stores the type of floating point
        static constexpr bool is_iec559{false};
        /// @brief stores whether or not T is bounded
        static constexpr bool is_bounded{false};
        /// @brief stores whether or not T handles overflow with modulo
        static constexpr bool is_modulo{false};
        /// @brief stores the number of radix digits for T
        static constexpr bsl::int32 digits{0};
        /// @brief stores the number of base 10 digits for T
        static constexpr bsl::int32 digits10{0};
        /// @brief stores the number of base 10 digits to diff T
        static constexpr bsl::int32 max_digits10{0};
        /// @brief stores the integer base that presents digits
        static constexpr bsl::int32 radix{0};
        /// @brief stores the smallest negative exponential number
        static constexpr bsl::int32 min_exponent{0};
        /// @brief stores the smallest negative exponential number in base 10
        static constexpr bsl::int32 min_exponent10{0};
        /// @brief stores the largest positive exponential number
        static constexpr bsl::int32 max_exponent{0};
        /// @brief stores the largest positive exponential number in base 10
        static constexpr bsl::int32 max_exponent10{0};
        /// @brief stores whether T can generate a trap
        static constexpr bool traps{false};
        /// @brief stores whether or T detected tinyness before rounding
        static constexpr bool tinyness_before{false};

        /// <!-- description -->
        ///   @brief Returns the min value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the min value of T
        ///
        static constexpr T
        min() noexcept
        {
            return {};
        }

        /// <!-- description -->
        ///   @brief Returns the lowest value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the lowest value of T
        ///
        static constexpr T
        lowest() noexcept
        {
            return {};
        }

        /// <!-- description -->
        ///   @brief Returns the max value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        static constexpr T
        max() noexcept
        {
            return {};
        }

        /// <!-- description -->
        ///   @brief Returns the floating point resolution
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        static constexpr T
        epsilon() noexcept
        {
            return {};
        }

        /// <!-- description -->
        ///   @brief Returns the rounding error of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the rounding error of T
        ///
        static constexpr T
        round_error() noexcept
        {
            return {};
        }

        /// <!-- description -->
        ///   @brief Returns the value of infinity for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of infinity for T
        ///
        static constexpr T
        infinity() noexcept
        {
            return {};
        }

        /// <!-- description -->
        ///   @brief Returns the quiet NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the quiet NaN value for T
        ///
        static constexpr T
        quiet_NaN() noexcept
        {
            return {};
        }

        /// <!-- description -->
        ///   @brief Returns the signaling NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the signaling NaN value for T
        ///
        static constexpr T
        signaling_NaN() noexcept
        {
            return {};
        }

        /// <!-- description -->
        ///   @brief Returns the smallest subnormal value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the smallest subnormal value for T
        ///
        static constexpr T
        denorm_min() noexcept
        {
            return {};
        }
    };

    /// @cond doxygen off

    /// @class bsl::numeric_limits
    ///
    /// <!-- description -->
    ///   @brief Implements std::numeric_limits
    ///   @include example_numeric_limits_overview.hpp
    ///
    template<>
    struct numeric_limits<bool> final
    {
        /// @brief stores whether or not this is a specialization
        static constexpr bool is_specialized{true};
        /// @brief stores whether or not T is signed
        static constexpr bool is_signed{false};
        /// @brief stores whether or not T is an integer
        static constexpr bool is_integer{true};
        /// @brief stores whether or not T is exact
        static constexpr bool is_exact{true};
        /// @brief stores whether or not T has defined infinity
        static constexpr bool has_infinity{false};
        /// @brief stores whether or not T has a quiet NaN
        static constexpr bool has_quiet_NaN{false};
        /// @brief stores whether or not T has a signaling NaN
        static constexpr bool has_signaling_NaN{false};
        /// @brief stores the denorm style of T
        static constexpr float_denorm_style has_denorm{float_denorm_style::denorm_absent};
        /// @brief stores whether or not floating points detect loss
        static constexpr bool has_denorm_loss{false};
        /// @brief stores the rounding style of T
        static constexpr float_round_style round_style{float_round_style::round_toward_zero};
        /// @brief stores the type of floating point
        static constexpr bool is_iec559{false};
        /// @brief stores whether or not T is bounded
        static constexpr bool is_bounded{true};
        /// @brief stores whether or not T handles overflow with modulo
        static constexpr bool is_modulo{false};
        /// @brief stores the number of radix digits for T
        static constexpr bsl::int32 digits{1};
        /// @brief stores the number of base 10 digits for T
        static constexpr bsl::int32 digits10{0};
        /// @brief stores the number of base 10 digits to diff T
        static constexpr bsl::int32 max_digits10{0};
        /// @brief stores the integer base that presents digits
        static constexpr bsl::int32 radix{2};
        /// @brief stores the smallest negative exponential number
        static constexpr bsl::int32 min_exponent{0};
        /// @brief stores the smallest negative exponential number in base 10
        static constexpr bsl::int32 min_exponent10{0};
        /// @brief stores the largest positive exponential number
        static constexpr bsl::int32 max_exponent{0};
        /// @brief stores the largest positive exponential number in base 10
        static constexpr bsl::int32 max_exponent10{0};
        /// @brief stores whether T can generate a trap
        static constexpr bool traps{false};
        /// @brief stores whether or T detected tinyness before rounding
        static constexpr bool tinyness_before{false};

        /// <!-- description -->
        ///   @brief Returns the min value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the min value of T
        ///
        static constexpr bool
        min() noexcept
        {
            return false;
        }

        /// <!-- description -->
        ///   @brief Returns the lowest value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the lowest value of T
        ///
        static constexpr bool
        lowest() noexcept
        {
            return false;
        }

        /// <!-- description -->
        ///   @brief Returns the max value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        static constexpr bool
        max() noexcept
        {
            return true;
        }

        /// <!-- description -->
        ///   @brief Returns the floating point resolution
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        static constexpr bool
        epsilon() noexcept
        {
            return false;
        }

        /// <!-- description -->
        ///   @brief Returns the rounding error of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the rounding error of T
        ///
        static constexpr bool
        round_error() noexcept
        {
            return false;
        }

        /// <!-- description -->
        ///   @brief Returns the value of infinity for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of infinity for T
        ///
        static constexpr bool
        infinity() noexcept
        {
            return false;
        }

        /// <!-- description -->
        ///   @brief Returns the quiet NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the quiet NaN value for T
        ///
        static constexpr bool
        quiet_NaN() noexcept
        {
            return false;
        }

        /// <!-- description -->
        ///   @brief Returns the signaling NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the signaling NaN value for T
        ///
        static constexpr bool
        signaling_NaN() noexcept
        {
            return false;
        }

        /// <!-- description -->
        ///   @brief Returns the smallest subnormal value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the smallest subnormal value for T
        ///
        static constexpr bool
        denorm_min() noexcept
        {
            return false;
        }
    };

    /// @class bsl::numeric_limits
    ///
    /// <!-- description -->
    ///   @brief Implements std::numeric_limits
    ///   @include example_numeric_limits_overview.hpp
    ///
    template<>
    struct numeric_limits<bsl::int8> final
    {
        /// @brief stores whether or not this is a specialization
        static constexpr bool is_specialized{true};
        /// @brief stores whether or not T is signed
        static constexpr bool is_signed{true};
        /// @brief stores whether or not T is an integer
        static constexpr bool is_integer{true};
        /// @brief stores whether or not T is exact
        static constexpr bool is_exact{true};
        /// @brief stores whether or not T has defined infinity
        static constexpr bool has_infinity{false};
        /// @brief stores whether or not T has a quiet NaN
        static constexpr bool has_quiet_NaN{false};
        /// @brief stores whether or not T has a signaling NaN
        static constexpr bool has_signaling_NaN{false};
        /// @brief stores the denorm style of T
        static constexpr float_denorm_style has_denorm{float_denorm_style::denorm_absent};
        /// @brief stores whether or not floating points detect loss
        static constexpr bool has_denorm_loss{false};
        /// @brief stores the rounding style of T
        static constexpr float_round_style round_style{float_round_style::round_toward_zero};
        /// @brief stores the type of floating point
        static constexpr bool is_iec559{false};
        /// @brief stores whether or not T is bounded
        static constexpr bool is_bounded{true};
        /// @brief stores whether or not T handles overflow with modulo
        static constexpr bool is_modulo{false};
        /// @brief stores the number of radix digits for T
        static constexpr bsl::int32 digits{(CHAR_BIT * sizeof(bsl::int8)) - 1};
        /// @brief stores the number of base 10 digits for T
        static constexpr bsl::int32 digits10{0};    // TODO... need to sort out the need for log10
        /// @brief stores the number of base 10 digits to diff T
        static constexpr bsl::int32 max_digits10{0};
        /// @brief stores the integer base that presents digits
        static constexpr bsl::int32 radix{2};
        /// @brief stores the smallest negative exponential number
        static constexpr bsl::int32 min_exponent{0};
        /// @brief stores the smallest negative exponential number in base 10
        static constexpr bsl::int32 min_exponent10{0};
        /// @brief stores the largest positive exponential number
        static constexpr bsl::int32 max_exponent{0};
        /// @brief stores the largest positive exponential number in base 10
        static constexpr bsl::int32 max_exponent10{0};
        /// @brief stores whether T can generate a trap
        static constexpr bool traps{false};
        /// @brief stores whether or T detected tinyness before rounding
        static constexpr bool tinyness_before{false};

        /// <!-- description -->
        ///   @brief Returns the min value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the min value of T
        ///
        static constexpr bsl::int8
        min() noexcept
        {
            return INT8_MIN;
        }

        /// <!-- description -->
        ///   @brief Returns the lowest value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the lowest value of T
        ///
        static constexpr bsl::int8
        lowest() noexcept
        {
            return INT8_MIN;
        }

        /// <!-- description -->
        ///   @brief Returns the max value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        static constexpr bsl::int8
        max() noexcept
        {
            return INT8_MAX;
        }

        /// <!-- description -->
        ///   @brief Returns the floating point resolution
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        static constexpr bsl::int8
        epsilon() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the rounding error of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the rounding error of T
        ///
        static constexpr bsl::int8
        round_error() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the value of infinity for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of infinity for T
        ///
        static constexpr bsl::int8
        infinity() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the quiet NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the quiet NaN value for T
        ///
        static constexpr bsl::int8
        quiet_NaN() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the signaling NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the signaling NaN value for T
        ///
        static constexpr bsl::int8
        signaling_NaN() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the smallest subnormal value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the smallest subnormal value for T
        ///
        static constexpr bsl::int8
        denorm_min() noexcept
        {
            return 0;
        }
    };

    /// @class bsl::numeric_limits
    ///
    /// <!-- description -->
    ///   @brief Implements std::numeric_limits
    ///   @include example_numeric_limits_overview.hpp
    ///
    template<>
    struct numeric_limits<bsl::int16> final
    {
        /// @brief stores whether or not this is a specialization
        static constexpr bool is_specialized{true};
        /// @brief stores whether or not T is signed
        static constexpr bool is_signed{true};
        /// @brief stores whether or not T is an integer
        static constexpr bool is_integer{true};
        /// @brief stores whether or not T is exact
        static constexpr bool is_exact{true};
        /// @brief stores whether or not T has defined infinity
        static constexpr bool has_infinity{false};
        /// @brief stores whether or not T has a quiet NaN
        static constexpr bool has_quiet_NaN{false};
        /// @brief stores whether or not T has a signaling NaN
        static constexpr bool has_signaling_NaN{false};
        /// @brief stores the denorm style of T
        static constexpr float_denorm_style has_denorm{float_denorm_style::denorm_absent};
        /// @brief stores whether or not floating points detect loss
        static constexpr bool has_denorm_loss{false};
        /// @brief stores the rounding style of T
        static constexpr float_round_style round_style{float_round_style::round_toward_zero};
        /// @brief stores the type of floating point
        static constexpr bool is_iec559{false};
        /// @brief stores whether or not T is bounded
        static constexpr bool is_bounded{true};
        /// @brief stores whether or not T handles overflow with modulo
        static constexpr bool is_modulo{false};
        /// @brief stores the number of radix digits for T
        static constexpr bsl::int32 digits{(CHAR_BIT * sizeof(bsl::int16)) - 1};
        /// @brief stores the number of base 10 digits for T
        static constexpr bsl::int32 digits10{0};    // TODO... need to sort out the need for log10
        /// @brief stores the number of base 10 digits to diff T
        static constexpr bsl::int32 max_digits10{0};
        /// @brief stores the integer base that presents digits
        static constexpr bsl::int32 radix{2};
        /// @brief stores the smallest negative exponential number
        static constexpr bsl::int32 min_exponent{0};
        /// @brief stores the smallest negative exponential number in base 10
        static constexpr bsl::int32 min_exponent10{0};
        /// @brief stores the largest positive exponential number
        static constexpr bsl::int32 max_exponent{0};
        /// @brief stores the largest positive exponential number in base 10
        static constexpr bsl::int32 max_exponent10{0};
        /// @brief stores whether T can generate a trap
        static constexpr bool traps{false};
        /// @brief stores whether or T detected tinyness before rounding
        static constexpr bool tinyness_before{false};

        /// <!-- description -->
        ///   @brief Returns the min value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the min value of T
        ///
        static constexpr bsl::int16
        min() noexcept
        {
            return INT16_MIN;
        }

        /// <!-- description -->
        ///   @brief Returns the lowest value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the lowest value of T
        ///
        static constexpr bsl::int16
        lowest() noexcept
        {
            return INT16_MIN;
        }

        /// <!-- description -->
        ///   @brief Returns the max value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        static constexpr bsl::int16
        max() noexcept
        {
            return INT16_MAX;
        }

        /// <!-- description -->
        ///   @brief Returns the floating point resolution
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        static constexpr bsl::int16
        epsilon() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the rounding error of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the rounding error of T
        ///
        static constexpr bsl::int16
        round_error() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the value of infinity for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of infinity for T
        ///
        static constexpr bsl::int16
        infinity() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the quiet NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the quiet NaN value for T
        ///
        static constexpr bsl::int16
        quiet_NaN() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the signaling NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the signaling NaN value for T
        ///
        static constexpr bsl::int16
        signaling_NaN() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the smallest subnormal value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the smallest subnormal value for T
        ///
        static constexpr bsl::int16
        denorm_min() noexcept
        {
            return 0;
        }
    };

    /// @class bsl::numeric_limits
    ///
    /// <!-- description -->
    ///   @brief Implements std::numeric_limits
    ///   @include example_numeric_limits_overview.hpp
    ///
    template<>
    struct numeric_limits<bsl::int32> final
    {
        /// @brief stores whether or not this is a specialization
        static constexpr bool is_specialized{true};
        /// @brief stores whether or not T is signed
        static constexpr bool is_signed{true};
        /// @brief stores whether or not T is an integer
        static constexpr bool is_integer{true};
        /// @brief stores whether or not T is exact
        static constexpr bool is_exact{true};
        /// @brief stores whether or not T has defined infinity
        static constexpr bool has_infinity{false};
        /// @brief stores whether or not T has a quiet NaN
        static constexpr bool has_quiet_NaN{false};
        /// @brief stores whether or not T has a signaling NaN
        static constexpr bool has_signaling_NaN{false};
        /// @brief stores the denorm style of T
        static constexpr float_denorm_style has_denorm{float_denorm_style::denorm_absent};
        /// @brief stores whether or not floating points detect loss
        static constexpr bool has_denorm_loss{false};
        /// @brief stores the rounding style of T
        static constexpr float_round_style round_style{float_round_style::round_toward_zero};
        /// @brief stores the type of floating point
        static constexpr bool is_iec559{false};
        /// @brief stores whether or not T is bounded
        static constexpr bool is_bounded{true};
        /// @brief stores whether or not T handles overflow with modulo
        static constexpr bool is_modulo{false};
        /// @brief stores the number of radix digits for T
        static constexpr bsl::int32 digits{(CHAR_BIT * sizeof(bsl::int32)) - 1};
        /// @brief stores the number of base 10 digits for T
        static constexpr bsl::int32 digits10{0};    // TODO... need to sort out the need for log10
        /// @brief stores the number of base 10 digits to diff T
        static constexpr bsl::int32 max_digits10{0};
        /// @brief stores the integer base that presents digits
        static constexpr bsl::int32 radix{2};
        /// @brief stores the smallest negative exponential number
        static constexpr bsl::int32 min_exponent{0};
        /// @brief stores the smallest negative exponential number in base 10
        static constexpr bsl::int32 min_exponent10{0};
        /// @brief stores the largest positive exponential number
        static constexpr bsl::int32 max_exponent{0};
        /// @brief stores the largest positive exponential number in base 10
        static constexpr bsl::int32 max_exponent10{0};
        /// @brief stores whether T can generate a trap
        static constexpr bool traps{false};
        /// @brief stores whether or T detected tinyness before rounding
        static constexpr bool tinyness_before{false};

        /// <!-- description -->
        ///   @brief Returns the min value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the min value of T
        ///
        static constexpr bsl::int32
        min() noexcept
        {
            return INT32_MIN;
        }

        /// <!-- description -->
        ///   @brief Returns the lowest value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the lowest value of T
        ///
        static constexpr bsl::int32
        lowest() noexcept
        {
            return INT32_MIN;
        }

        /// <!-- description -->
        ///   @brief Returns the max value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        static constexpr bsl::int32
        max() noexcept
        {
            return INT32_MAX;
        }

        /// <!-- description -->
        ///   @brief Returns the floating point resolution
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        static constexpr bsl::int32
        epsilon() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the rounding error of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the rounding error of T
        ///
        static constexpr bsl::int32
        round_error() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the value of infinity for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of infinity for T
        ///
        static constexpr bsl::int32
        infinity() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the quiet NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the quiet NaN value for T
        ///
        static constexpr bsl::int32
        quiet_NaN() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the signaling NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the signaling NaN value for T
        ///
        static constexpr bsl::int32
        signaling_NaN() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the smallest subnormal value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the smallest subnormal value for T
        ///
        static constexpr bsl::int32
        denorm_min() noexcept
        {
            return 0;
        }
    };

    /// @class bsl::numeric_limits
    ///
    /// <!-- description -->
    ///   @brief Implements std::numeric_limits
    ///   @include example_numeric_limits_overview.hpp
    ///
    template<>
    struct numeric_limits<bsl::int64> final
    {
        /// @brief stores whether or not this is a specialization
        static constexpr bool is_specialized{true};
        /// @brief stores whether or not T is signed
        static constexpr bool is_signed{true};
        /// @brief stores whether or not T is an integer
        static constexpr bool is_integer{true};
        /// @brief stores whether or not T is exact
        static constexpr bool is_exact{true};
        /// @brief stores whether or not T has defined infinity
        static constexpr bool has_infinity{false};
        /// @brief stores whether or not T has a quiet NaN
        static constexpr bool has_quiet_NaN{false};
        /// @brief stores whether or not T has a signaling NaN
        static constexpr bool has_signaling_NaN{false};
        /// @brief stores the denorm style of T
        static constexpr float_denorm_style has_denorm{float_denorm_style::denorm_absent};
        /// @brief stores whether or not floating points detect loss
        static constexpr bool has_denorm_loss{false};
        /// @brief stores the rounding style of T
        static constexpr float_round_style round_style{float_round_style::round_toward_zero};
        /// @brief stores the type of floating point
        static constexpr bool is_iec559{false};
        /// @brief stores whether or not T is bounded
        static constexpr bool is_bounded{true};
        /// @brief stores whether or not T handles overflow with modulo
        static constexpr bool is_modulo{false};
        /// @brief stores the number of radix digits for T
        static constexpr bsl::int32 digits{(CHAR_BIT * sizeof(bsl::int64)) - 1};
        /// @brief stores the number of base 10 digits for T
        static constexpr bsl::int32 digits10{0};    // TODO... need to sort out the need for log10
        /// @brief stores the number of base 10 digits to diff T
        static constexpr bsl::int32 max_digits10{0};
        /// @brief stores the integer base that presents digits
        static constexpr bsl::int32 radix{2};
        /// @brief stores the smallest negative exponential number
        static constexpr bsl::int32 min_exponent{0};
        /// @brief stores the smallest negative exponential number in base 10
        static constexpr bsl::int32 min_exponent10{0};
        /// @brief stores the largest positive exponential number
        static constexpr bsl::int32 max_exponent{0};
        /// @brief stores the largest positive exponential number in base 10
        static constexpr bsl::int32 max_exponent10{0};
        /// @brief stores whether T can generate a trap
        static constexpr bool traps{false};
        /// @brief stores whether or T detected tinyness before rounding
        static constexpr bool tinyness_before{false};

        /// <!-- description -->
        ///   @brief Returns the min value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the min value of T
        ///
        static constexpr bsl::int64
        min() noexcept
        {
            return INT64_MIN;
        }

        /// <!-- description -->
        ///   @brief Returns the lowest value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the lowest value of T
        ///
        static constexpr bsl::int64
        lowest() noexcept
        {
            return INT64_MIN;
        }

        /// <!-- description -->
        ///   @brief Returns the max value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        static constexpr bsl::int64
        max() noexcept
        {
            return INT64_MAX;
        }

        /// <!-- description -->
        ///   @brief Returns the floating point resolution
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        static constexpr bsl::int64
        epsilon() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the rounding error of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the rounding error of T
        ///
        static constexpr bsl::int64
        round_error() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the value of infinity for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of infinity for T
        ///
        static constexpr bsl::int64
        infinity() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the quiet NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the quiet NaN value for T
        ///
        static constexpr bsl::int64
        quiet_NaN() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the signaling NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the signaling NaN value for T
        ///
        static constexpr bsl::int64
        signaling_NaN() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the smallest subnormal value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the smallest subnormal value for T
        ///
        static constexpr bsl::int64
        denorm_min() noexcept
        {
            return 0;
        }
    };

    /// @class bsl::numeric_limits
    ///
    /// <!-- description -->
    ///   @brief Implements std::numeric_limits
    ///   @include example_numeric_limits_overview.hpp
    ///
    template<>
    struct numeric_limits<bsl::uint8> final
    {
        /// @brief stores whether or not this is a specialization
        static constexpr bool is_specialized{true};
        /// @brief stores whether or not T is signed
        static constexpr bool is_signed{false};
        /// @brief stores whether or not T is an integer
        static constexpr bool is_integer{true};
        /// @brief stores whether or not T is exact
        static constexpr bool is_exact{true};
        /// @brief stores whether or not T has defined infinity
        static constexpr bool has_infinity{false};
        /// @brief stores whether or not T has a quiet NaN
        static constexpr bool has_quiet_NaN{false};
        /// @brief stores whether or not T has a signaling NaN
        static constexpr bool has_signaling_NaN{false};
        /// @brief stores the denorm style of T
        static constexpr float_denorm_style has_denorm{float_denorm_style::denorm_absent};
        /// @brief stores whether or not floating points detect loss
        static constexpr bool has_denorm_loss{false};
        /// @brief stores the rounding style of T
        static constexpr float_round_style round_style{float_round_style::round_toward_zero};
        /// @brief stores the type of floating point
        static constexpr bool is_iec559{false};
        /// @brief stores whether or not T is bounded
        static constexpr bool is_bounded{true};
        /// @brief stores whether or not T handles overflow with modulo
        static constexpr bool is_modulo{true};
        /// @brief stores the number of radix digits for T
        static constexpr bsl::int32 digits{(CHAR_BIT * sizeof(bsl::uint8))};
        /// @brief stores the number of base 10 digits for T
        static constexpr bsl::int32 digits10{0};    // TODO... need to sort out the need for log10
        /// @brief stores the number of base 10 digits to diff T
        static constexpr bsl::int32 max_digits10{0};
        /// @brief stores the integer base that presents digits
        static constexpr bsl::int32 radix{2};
        /// @brief stores the smallest negative exponential number
        static constexpr bsl::int32 min_exponent{0};
        /// @brief stores the smallest negative exponential number in base 10
        static constexpr bsl::int32 min_exponent10{0};
        /// @brief stores the largest positive exponential number
        static constexpr bsl::int32 max_exponent{0};
        /// @brief stores the largest positive exponential number in base 10
        static constexpr bsl::int32 max_exponent10{0};
        /// @brief stores whether T can generate a trap
        static constexpr bool traps{false};
        /// @brief stores whether or T detected tinyness before rounding
        static constexpr bool tinyness_before{false};

        /// <!-- description -->
        ///   @brief Returns the min value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the min value of T
        ///
        static constexpr bsl::uint8
        min() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the lowest value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the lowest value of T
        ///
        static constexpr bsl::uint8
        lowest() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the max value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        static constexpr bsl::uint8
        max() noexcept
        {
            return UINT8_MAX;
        }

        /// <!-- description -->
        ///   @brief Returns the floating point resolution
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        static constexpr bsl::uint8
        epsilon() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the rounding error of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the rounding error of T
        ///
        static constexpr bsl::uint8
        round_error() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the value of infinity for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of infinity for T
        ///
        static constexpr bsl::uint8
        infinity() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the quiet NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the quiet NaN value for T
        ///
        static constexpr bsl::uint8
        quiet_NaN() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the signaling NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the signaling NaN value for T
        ///
        static constexpr bsl::uint8
        signaling_NaN() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the smallest subnormal value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the smallest subnormal value for T
        ///
        static constexpr bsl::uint8
        denorm_min() noexcept
        {
            return 0;
        }
    };

    /// @class bsl::numeric_limits
    ///
    /// <!-- description -->
    ///   @brief Implements std::numeric_limits
    ///   @include example_numeric_limits_overview.hpp
    ///
    template<>
    struct numeric_limits<bsl::uint16> final
    {
        /// @brief stores whether or not this is a specialization
        static constexpr bool is_specialized{true};
        /// @brief stores whether or not T is signed
        static constexpr bool is_signed{false};
        /// @brief stores whether or not T is an integer
        static constexpr bool is_integer{true};
        /// @brief stores whether or not T is exact
        static constexpr bool is_exact{true};
        /// @brief stores whether or not T has defined infinity
        static constexpr bool has_infinity{false};
        /// @brief stores whether or not T has a quiet NaN
        static constexpr bool has_quiet_NaN{false};
        /// @brief stores whether or not T has a signaling NaN
        static constexpr bool has_signaling_NaN{false};
        /// @brief stores the denorm style of T
        static constexpr float_denorm_style has_denorm{float_denorm_style::denorm_absent};
        /// @brief stores whether or not floating points detect loss
        static constexpr bool has_denorm_loss{false};
        /// @brief stores the rounding style of T
        static constexpr float_round_style round_style{float_round_style::round_toward_zero};
        /// @brief stores the type of floating point
        static constexpr bool is_iec559{false};
        /// @brief stores whether or not T is bounded
        static constexpr bool is_bounded{true};
        /// @brief stores whether or not T handles overflow with modulo
        static constexpr bool is_modulo{true};
        /// @brief stores the number of radix digits for T
        static constexpr bsl::int32 digits{(CHAR_BIT * sizeof(bsl::uint16))};
        /// @brief stores the number of base 10 digits for T
        static constexpr bsl::int32 digits10{0};    // TODO... need to sort out the need for log10
        /// @brief stores the number of base 10 digits to diff T
        static constexpr bsl::int32 max_digits10{0};
        /// @brief stores the integer base that presents digits
        static constexpr bsl::int32 radix{2};
        /// @brief stores the smallest negative exponential number
        static constexpr bsl::int32 min_exponent{0};
        /// @brief stores the smallest negative exponential number in base 10
        static constexpr bsl::int32 min_exponent10{0};
        /// @brief stores the largest positive exponential number
        static constexpr bsl::int32 max_exponent{0};
        /// @brief stores the largest positive exponential number in base 10
        static constexpr bsl::int32 max_exponent10{0};
        /// @brief stores whether T can generate a trap
        static constexpr bool traps{false};
        /// @brief stores whether or T detected tinyness before rounding
        static constexpr bool tinyness_before{false};

        /// <!-- description -->
        ///   @brief Returns the min value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the min value of T
        ///
        static constexpr bsl::uint16
        min() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the lowest value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the lowest value of T
        ///
        static constexpr bsl::uint16
        lowest() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the max value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        static constexpr bsl::uint16
        max() noexcept
        {
            return UINT16_MAX;
        }

        /// <!-- description -->
        ///   @brief Returns the floating point resolution
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        static constexpr bsl::uint16
        epsilon() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the rounding error of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the rounding error of T
        ///
        static constexpr bsl::uint16
        round_error() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the value of infinity for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of infinity for T
        ///
        static constexpr bsl::uint16
        infinity() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the quiet NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the quiet NaN value for T
        ///
        static constexpr bsl::uint16
        quiet_NaN() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the signaling NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the signaling NaN value for T
        ///
        static constexpr bsl::uint16
        signaling_NaN() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the smallest subnormal value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the smallest subnormal value for T
        ///
        static constexpr bsl::uint16
        denorm_min() noexcept
        {
            return 0;
        }
    };

    /// @class bsl::numeric_limits
    ///
    /// <!-- description -->
    ///   @brief Implements std::numeric_limits
    ///   @include example_numeric_limits_overview.hpp
    ///
    template<>
    struct numeric_limits<bsl::uint32> final
    {
        /// @brief stores whether or not this is a specialization
        static constexpr bool is_specialized{true};
        /// @brief stores whether or not T is signed
        static constexpr bool is_signed{false};
        /// @brief stores whether or not T is an integer
        static constexpr bool is_integer{true};
        /// @brief stores whether or not T is exact
        static constexpr bool is_exact{true};
        /// @brief stores whether or not T has defined infinity
        static constexpr bool has_infinity{false};
        /// @brief stores whether or not T has a quiet NaN
        static constexpr bool has_quiet_NaN{false};
        /// @brief stores whether or not T has a signaling NaN
        static constexpr bool has_signaling_NaN{false};
        /// @brief stores the denorm style of T
        static constexpr float_denorm_style has_denorm{float_denorm_style::denorm_absent};
        /// @brief stores whether or not floating points detect loss
        static constexpr bool has_denorm_loss{false};
        /// @brief stores the rounding style of T
        static constexpr float_round_style round_style{float_round_style::round_toward_zero};
        /// @brief stores the type of floating point
        static constexpr bool is_iec559{false};
        /// @brief stores whether or not T is bounded
        static constexpr bool is_bounded{true};
        /// @brief stores whether or not T handles overflow with modulo
        static constexpr bool is_modulo{true};
        /// @brief stores the number of radix digits for T
        static constexpr bsl::int32 digits{(CHAR_BIT * sizeof(bsl::uint32))};
        /// @brief stores the number of base 10 digits for T
        static constexpr bsl::int32 digits10{0};    // TODO... need to sort out the need for log10
        /// @brief stores the number of base 10 digits to diff T
        static constexpr bsl::int32 max_digits10{0};
        /// @brief stores the integer base that presents digits
        static constexpr bsl::int32 radix{2};
        /// @brief stores the smallest negative exponential number
        static constexpr bsl::int32 min_exponent{0};
        /// @brief stores the smallest negative exponential number in base 10
        static constexpr bsl::int32 min_exponent10{0};
        /// @brief stores the largest positive exponential number
        static constexpr bsl::int32 max_exponent{0};
        /// @brief stores the largest positive exponential number in base 10
        static constexpr bsl::int32 max_exponent10{0};
        /// @brief stores whether T can generate a trap
        static constexpr bool traps{false};
        /// @brief stores whether or T detected tinyness before rounding
        static constexpr bool tinyness_before{false};

        /// <!-- description -->
        ///   @brief Returns the min value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the min value of T
        ///
        static constexpr bsl::uint32
        min() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the lowest value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the lowest value of T
        ///
        static constexpr bsl::uint32
        lowest() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the max value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        static constexpr bsl::uint32
        max() noexcept
        {
            return UINT32_MAX;
        }

        /// <!-- description -->
        ///   @brief Returns the floating point resolution
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        static constexpr bsl::uint32
        epsilon() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the rounding error of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the rounding error of T
        ///
        static constexpr bsl::uint32
        round_error() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the value of infinity for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of infinity for T
        ///
        static constexpr bsl::uint32
        infinity() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the quiet NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the quiet NaN value for T
        ///
        static constexpr bsl::uint32
        quiet_NaN() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the signaling NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the signaling NaN value for T
        ///
        static constexpr bsl::uint32
        signaling_NaN() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the smallest subnormal value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the smallest subnormal value for T
        ///
        static constexpr bsl::uint32
        denorm_min() noexcept
        {
            return 0;
        }
    };

    /// @class bsl::numeric_limits
    ///
    /// <!-- description -->
    ///   @brief Implements std::numeric_limits
    ///   @include example_numeric_limits_overview.hpp
    ///
    template<>
    struct numeric_limits<bsl::uint64> final
    {
        /// @brief stores whether or not this is a specialization
        static constexpr bool is_specialized{true};
        /// @brief stores whether or not T is signed
        static constexpr bool is_signed{false};
        /// @brief stores whether or not T is an integer
        static constexpr bool is_integer{true};
        /// @brief stores whether or not T is exact
        static constexpr bool is_exact{true};
        /// @brief stores whether or not T has defined infinity
        static constexpr bool has_infinity{false};
        /// @brief stores whether or not T has a quiet NaN
        static constexpr bool has_quiet_NaN{false};
        /// @brief stores whether or not T has a signaling NaN
        static constexpr bool has_signaling_NaN{false};
        /// @brief stores the denorm style of T
        static constexpr float_denorm_style has_denorm{float_denorm_style::denorm_absent};
        /// @brief stores whether or not floating points detect loss
        static constexpr bool has_denorm_loss{false};
        /// @brief stores the rounding style of T
        static constexpr float_round_style round_style{float_round_style::round_toward_zero};
        /// @brief stores the type of floating point
        static constexpr bool is_iec559{false};
        /// @brief stores whether or not T is bounded
        static constexpr bool is_bounded{true};
        /// @brief stores whether or not T handles overflow with modulo
        static constexpr bool is_modulo{true};
        /// @brief stores the number of radix digits for T
        static constexpr bsl::int32 digits{(CHAR_BIT * sizeof(bsl::uint64))};
        /// @brief stores the number of base 10 digits for T
        static constexpr bsl::int32 digits10{0};    // TODO... need to sort out the need for log10
        /// @brief stores the number of base 10 digits to diff T
        static constexpr bsl::int32 max_digits10{0};
        /// @brief stores the integer base that presents digits
        static constexpr bsl::int32 radix{2};
        /// @brief stores the smallest negative exponential number
        static constexpr bsl::int32 min_exponent{0};
        /// @brief stores the smallest negative exponential number in base 10
        static constexpr bsl::int32 min_exponent10{0};
        /// @brief stores the largest positive exponential number
        static constexpr bsl::int32 max_exponent{0};
        /// @brief stores the largest positive exponential number in base 10
        static constexpr bsl::int32 max_exponent10{0};
        /// @brief stores whether T can generate a trap
        static constexpr bool traps{false};
        /// @brief stores whether or T detected tinyness before rounding
        static constexpr bool tinyness_before{false};

        /// <!-- description -->
        ///   @brief Returns the min value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the min value of T
        ///
        static constexpr bsl::uint64
        min() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the lowest value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the lowest value of T
        ///
        static constexpr bsl::uint64
        lowest() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the max value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        static constexpr bsl::uint64
        max() noexcept
        {
            return UINT64_MAX;
        }

        /// <!-- description -->
        ///   @brief Returns the floating point resolution
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        static constexpr bsl::uint64
        epsilon() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the rounding error of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the rounding error of T
        ///
        static constexpr bsl::uint64
        round_error() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the value of infinity for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of infinity for T
        ///
        static constexpr bsl::uint64
        infinity() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the quiet NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the quiet NaN value for T
        ///
        static constexpr bsl::uint64
        quiet_NaN() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the signaling NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the signaling NaN value for T
        ///
        static constexpr bsl::uint64
        signaling_NaN() noexcept
        {
            return 0;
        }

        /// <!-- description -->
        ///   @brief Returns the smallest subnormal value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the smallest subnormal value for T
        ///
        static constexpr bsl::uint64
        denorm_min() noexcept
        {
            return 0;
        }
    };

    /// @class bsl::numeric_limits
    ///
    /// <!-- description -->
    ///   @brief Implements std::numeric_limits
    ///   @include example_numeric_limits_overview.hpp
    ///
    template<>
    struct numeric_limits<char> final
    {
        // char not supported
    };

    /// @class bsl::numeric_limits
    ///
    /// <!-- description -->
    ///   @brief Implements std::numeric_limits
    ///   @include example_numeric_limits_overview.hpp
    ///
    template<>
    struct numeric_limits<wchar_t> final
    {
        // wchar_t not supported
    };

    /// @class bsl::numeric_limits
    ///
    /// <!-- description -->
    ///   @brief Implements std::numeric_limits
    ///   @include example_numeric_limits_overview.hpp
    ///
    template<>
    struct numeric_limits<char16_t> final
    {
        // char16_t not supported
    };

    /// @class bsl::numeric_limits
    ///
    /// <!-- description -->
    ///   @brief Implements std::numeric_limits
    ///   @include example_numeric_limits_overview.hpp
    ///
    template<>
    struct numeric_limits<char32_t> final
    {
        // char32_t not supported
    };

    /// @class bsl::numeric_limits
    ///
    /// <!-- description -->
    ///   @brief Implements std::numeric_limits
    ///   @include example_numeric_limits_overview.hpp
    ///
    template<>
    struct numeric_limits<float> final
    {
        // float not supported
    };

    /// @class bsl::numeric_limits
    ///
    /// <!-- description -->
    ///   @brief Implements std::numeric_limits
    ///   @include example_numeric_limits_overview.hpp
    ///
    template<>
    struct numeric_limits<double> final
    {
        // double not supported
    };

    /// @class bsl::numeric_limits
    ///
    /// <!-- description -->
    ///   @brief Implements std::numeric_limits
    ///   @include example_numeric_limits_overview.hpp
    ///
    template<>
    struct numeric_limits<long double> final
    {
        // long double not supported
    };

    /// @endcond doxygen on
}

#endif
