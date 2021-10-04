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

#ifndef BSL_CSTDLIB_HPP
#define BSL_CSTDLIB_HPP

#include <bsl/is_constant_evaluated.hpp>
#include <bsl/touch.hpp>

namespace bsl
{
    /// <!-- description -->
    ///   @brief Implements the ABI for intrinsic_assert.
    ///
    extern "C" void HYPERVISOR_INTRINSIC_ASSERT_NAME() noexcept;    // NOLINT

    /// <!-- description -->
    ///   @brief Immediately the application with a failure
    ///
    [[noreturn]] constexpr void
    stdlib_fast_fail() noexcept    // GRCOV_EXCLUDE
    {
        if (bsl::is_constant_evaluated()) {        // GRCOV_EXCLUDE
            bsl::touch();                          // GRCOV_EXCLUDE
        }                                          // GRCOV_EXCLUDE
        else {                                     // GRCOV_EXCLUDE
            HYPERVISOR_INTRINSIC_ASSERT_NAME();    // GRCOV_EXCLUDE
        }                                          // GRCOV_EXCLUDE

        // Unreachable
        while (true) {    // GRCOV_EXCLUDE
        }                 // GRCOV_EXCLUDE
    }
}

#endif
