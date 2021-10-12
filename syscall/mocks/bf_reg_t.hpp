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

#ifndef BF_REG_T_HPP
#define BF_REG_T_HPP

#include <bsl/cstdint.hpp>

namespace syscall
{
    /// @brief stores the max value for a bf_reg_t
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    constexpr bsl::uint64 BF_MAX_REG_T{static_cast<bsl::uint64>(2)};

    /// <!-- description -->
    ///   @brief Defines which register to use for read/write
    ///
    enum class bf_reg_t : bsl::uint64
    {
        /// @brief defines an unsupported register
        bf_reg_t_unsupported = static_cast<bsl::uint64>(0),
        /// @brief defines as dummy bf_reg_t
        bf_reg_t_dummy = static_cast<bsl::uint64>(1),
        /// @brief defines an invalid bf_reg_t
        bf_reg_t_invalid = static_cast<bsl::uint64>(BF_MAX_REG_T)
    };
}

#endif
