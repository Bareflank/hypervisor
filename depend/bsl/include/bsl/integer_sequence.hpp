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
/// @file integer_sequence.hpp
///

#ifndef BSL_INTEGER_SEQUENCE_HPP
#define BSL_INTEGER_SEQUENCE_HPP

#include "details/integer_sequence_max.hpp"
#include "details/integer_sequence_min.hpp"

#include "cstdint.hpp"
#include "value_type_identity.hpp"

namespace bsl
{
    /// @class bsl::integer_sequence
    ///
    /// <!-- description -->
    ///   @brief The class template std::integer_sequence represents a
    ///     compile-time sequence of integers. When used as an argument to a
    ///     function template, the parameter pack Ints can be deduced and used
    ///     in pack expansion.
    ///   @include example_integer_sequence_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type that defines the sequence of integers
    ///   @tparam INTS the integers that make up the integer sequence
    ///
    template<typename T, T... INTS>
    class integer_sequence final : public value_type_identity<T>
    {
    public:
        /// <!-- description -->
        ///   @brief Equivalent to sizeof...(INTS)
        ///   @include integer_sequence/example_integer_sequence_size.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Equivalent to sizeof...(INTS)
        ///
        [[nodiscard]] static constexpr bsl::uintmax
        size() noexcept
        {
            return sizeof...(INTS);
        }

        /// <!-- description -->
        ///   @brief Returns the max integer in the sequence
        ///   @include integer_sequence/example_integer_sequence_max.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max integer in the sequence
        ///
        [[nodiscard]] static constexpr T
        max() noexcept
        {
            return details::integer_sequence_max<T, INTS...>::value;
        }

        /// <!-- description -->
        ///   @brief Returns the min integer in the sequence
        ///   @include integer_sequence/example_integer_sequence_min.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the min integer in the sequence
        ///
        [[nodiscard]] static constexpr T
        min() noexcept
        {
            return details::integer_sequence_min<T, INTS...>::value;
        }
    };

    /// @brief helper alias template for the common case of bsl::uintmax
    template<bsl::uintmax... INTS>
    using index_sequence = integer_sequence<bsl::uintmax, INTS...>;

    /// @brief helper alias that makes integer sequences
    template<typename T, T N>
    using make_integer_sequence = __make_integer_seq<integer_sequence, T, N>;

    /// @brief helper alias that makes integer sequences for bsl::uintmax
    template<bsl::uintmax N>
    using make_index_sequence = make_integer_sequence<bsl::uintmax, N>;

    /// @brief helper alias that makes an index sequence given a list of types
    template<typename... T>
    using index_sequence_for = make_index_sequence<sizeof...(T)>;
}

#endif
