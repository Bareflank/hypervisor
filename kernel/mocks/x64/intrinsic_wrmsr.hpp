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

#ifndef MOCKS_INTRINSIC_WRMSR_HPP
#define MOCKS_INTRINSIC_WRMSR_HPP

#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Implements intrinsic_t::wrmsr
    ///
    /// <!-- inputs/outputs -->
    ///   @param msr n/a
    ///   @param val n/a
    ///   @return n/a
    ///
    [[nodiscard]] constexpr auto
    intrinsic_wrmsr(bsl::uint32 const msr, bsl::uint64 const val) noexcept -> bsl::errc_type
    {
        bsl::discard(val);

        if (msr != bsl::safe_u32::magic_0()) {
            return bsl::errc_failure;
        }

        return bsl::errc_success;
    }
}

#endif
