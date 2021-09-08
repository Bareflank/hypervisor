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

#include "../../../src/dispatch_bootstrap.hpp"

#include <bf_syscall_t.hpp>
#include <tls_t.hpp>
#include <vp_pool_t.hpp>
#include <vs_pool_t.hpp>

#include <bsl/errc_type.hpp>
#include <bsl/ut.hpp>

namespace example
{
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
        bsl::ut_scenario{"default"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                tls_t mut_tls{};
                syscall::bf_syscall_t mut_sys{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        dispatch_bootstrap({}, mut_tls, mut_sys, {}, mut_vp_pool, mut_vs_pool, {}));
                };
            };
        };

        bsl::ut_scenario{"tls_initialize fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                tls_t mut_tls{};
                syscall::bf_syscall_t mut_sys{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.test_ret = bsl::errc_failure;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!dispatch_bootstrap(
                            {}, mut_tls, mut_sys, {}, mut_vp_pool, mut_vs_pool, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"vp_pool.allocate() fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                tls_t mut_tls{};
                syscall::bf_syscall_t mut_sys{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vp_pool.set_allocate_fails({}, {});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!dispatch_bootstrap(
                            {}, mut_tls, mut_sys, {}, mut_vp_pool, mut_vs_pool, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"vs_pool.allocate() fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                tls_t mut_tls{};
                syscall::bf_syscall_t mut_sys{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs_pool.set_allocate_fails({}, {});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!dispatch_bootstrap(
                            {}, mut_tls, mut_sys, {}, mut_vp_pool, mut_vs_pool, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"bf_vs_op_run fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                tls_t mut_tls{};
                syscall::bf_syscall_t mut_sys{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_sys.set_bf_vs_op_run({}, {}, {}, bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!dispatch_bootstrap(
                            {}, mut_tls, mut_sys, {}, mut_vp_pool, mut_vs_pool, {}));
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

    static_assert(example::tests() == bsl::ut_success());
    return example::tests();
}
