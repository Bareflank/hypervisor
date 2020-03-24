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
/// @file aligned_union.hpp
///

#ifndef BSL_ALIGNED_UNION_HPP
#define BSL_ALIGNED_UNION_HPP

#include "byte.hpp"
#include "cstdint.hpp"
#include "integer_sequence.hpp"

namespace bsl
{
    /// @class bsl::aligned_union
    ///
    /// <!-- description -->
    ///   @brief Implements the std::aligned_union interface. The
    ///     only real difference is we use "m_data" instead of "data" to
    ///     represent the member variable name.
    ///   @include example_aligned_union_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam GUARD used to prevent you from creating an aligned_union
    ///     and not an aligned_union_t
    ///   @tparam LEN the size of the storage buffer in bytes
    ///   @tparam TYPES the types that make up the union
    ///
    template<typename GUARD, bsl::uintmax LEN, typename... TYPES>
    struct aligned_union final
    {
        static_assert(sizeof...(TYPES) > 0, "empty aligned_union is not supported");

        /// @brief the alignment of the union.
        static constexpr bsl::uintmax alignment_value{index_sequence<alignof(TYPES)...>::max()};

        /// @class bsl::aligned_union::type
        ///
        /// <!-- description -->
        ///   @brief Implements the std::aligned_union type interface.
        ///
        struct type
        {
            /// @brief defines the storage component of the bsl::aligned_union
            alignas(alignment_value) byte m_data[    // NOLINT
                index_sequence<LEN, sizeof(TYPES)...>::max()];
        };
    };

    /// @brief a helper that reduces the verbosity of bsl::aligned_union
    template<bsl::uintmax LEN, typename... TYPES>
    using aligned_union_t = typename aligned_union<void, LEN, TYPES...>::type;
}

#endif
