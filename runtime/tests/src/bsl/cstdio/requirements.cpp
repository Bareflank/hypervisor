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

#include "../../../../src/bsl/cstdio.hpp"

#include <bsl/char_type.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/discard.hpp>
#include <bsl/ut.hpp>

namespace
{
    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_write_c.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///
    extern "C" inline void
    bf_debug_op_write_c_impl(bsl::char_type const reg0_in) noexcept
    {
        bsl::discard(reg0_in);
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_write_str.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///
    extern "C" inline void
    bf_debug_op_write_str_impl(
        bsl::char_type const *const reg0_in, bsl::uintmx const reg1_in) noexcept
    {
        bsl::discard(reg0_in);
        bsl::discard(reg1_in);
    }
}

/// <!-- description -->
///   @brief Main function for this unit test. If a call to bsl::ut_check() fails
///     the application will fast fail. If all calls to bsl::ut_check() pass, this
///     function will successfully return with bsl::exit_success.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
[[nodiscard]] auto
main() noexcept -> bsl::exit_code
{
    bf_debug_op_write_c_impl('*');
    bf_debug_op_write_str_impl("the answer is 42", {});

    bsl::ut_scenario{"verify noexcept"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            bsl::ut_then{} = []() noexcept {
                static_assert(noexcept(bsl::stdio_out_char('*')));
                static_assert(noexcept(bsl::stdio_out_cstr("the answer is 42", {})));
            };
        };
    };

    return bsl::ut_success();
}
