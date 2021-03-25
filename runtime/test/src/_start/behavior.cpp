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

#include <bsl/ut.hpp>

namespace mk
{
    /// @brief stores when ext_main_entry have been executed
    constinit bool g_ext_main_entry_executed{};
    /// @brief stores when bf_control_op_exit_impl have been executed
    constinit bool g_bf_control_op_exit_impl_executed{};

    /// <!-- description -->
    ///   @brief Defines a prototype for the _start function
    ///
    extern "C" void ut_start() noexcept;

    /// <!-- description -->
    ///   @brief Defines a mock of the ext_main_entry function
    ///
    extern "C" void
    ext_main_entry() noexcept
    {
        g_ext_main_entry_executed = true;
    }

    /// <!-- description -->
    ///   @brief Defines a mock of the bf_control_op_exit_impl function
    ///
    extern "C" void
    bf_control_op_exit_impl() noexcept
    {
        g_bf_control_op_exit_impl_executed = true;
    }

    /// <!-- description -->
    ///   @brief Used to execute the actual checks. We put the checks in this
    ///     function so that we can validate the tests both at compile-time
    ///     and at run-time. If a bsl::ut_check fails, the tests will either
    ///     fail fast at run-time, or will produce a compile-time error.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Always returns bsl::exit_success.
    ///
    [[nodiscard]] constexpr auto
    tests() noexcept -> bsl::exit_code
    {
        bsl::ut_scenario{"_start executes properly"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::ut_when{} = []() noexcept {
                    ut_start();
                    bsl::ut_then{} = []() noexcept {
                        bsl::ut_check(g_ext_main_entry_executed);
                        bsl::ut_check(g_bf_control_op_exit_impl_executed);
                    };
                };
            };
        };

        return bsl::ut_success();
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
    bsl::enable_color();

    static_assert(mk::tests() == bsl::ut_success());
    return mk::tests();
}
