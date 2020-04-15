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
/// @file aligned_storage.hpp
///

#ifndef BSL_ALIGNED_STORAGE_HPP
#define BSL_ALIGNED_STORAGE_HPP

#include "cstdint.hpp"
#include "byte.hpp"

namespace bsl
{
    /// @class bsl::aligned_storage
    ///
    /// <!-- description -->
    ///   @brief Implements the std::aligned_storage interface. The
    ///     only real difference is we use "m_data" instead of "data" to
    ///     represent the member variable name.
    ///   @include example_aligned_storage_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam GUARD used to prevent you from creating an aligned_storage
    ///     and not an aligned_storage_t
    ///   @tparam N the size of the storage buffer in bytes
    ///   @tparam A the alignment of the sotrage buffer. This defaults to
    ///     0, which means this is "unaligned" by default.
    ///
    template<typename GUARD, bsl::uintmax N, bsl::uintmax A = 0>
    struct aligned_storage final
    {
        static_assert(N > 0, "empty aligned_storage is not supported");

        /// @class bsl::aligned_storage::type
        ///
        /// <!-- description -->
        ///   @brief Implements the std::aligned_storage type interface.
        ///
        struct type final
        {
            /// @brief an array that provides the underlying storage
            alignas(A) byte m_data[N];    // NOLINT
        };
    };

    /// @brief a helper that reduces the verbosity of bsl::aligned_storage
    template<bsl::uintmax N, bsl::uintmax A = 0>
    using aligned_storage_t = typename aligned_storage<void, N, A>::type;
}

#endif
