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

#include "../../../../src/x64/dispatch_vmexit_cpuid.hpp"

#include <bf_syscall_t.hpp>
#include <cpuid_commands.hpp>

#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>
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
                syscall::bf_syscall_t mut_sys{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(dispatch_vmexit_cpuid({}, {}, mut_sys, {}, {}));
                };
            };
        };

        bsl::ut_scenario{"stop command"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                syscall::bf_syscall_t mut_sys{};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_sys.bf_tls_set_rax(bsl::to_u64(loader::CPUID_COMMAND_EAX));
                    mut_sys.bf_tls_set_rcx(bsl::to_u64(loader::CPUID_COMMAND_ECX_STOP));
                    mut_sys.bf_tls_set_online_pps(online_pps);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(dispatch_vmexit_cpuid({}, {}, mut_sys, {}, {}));
                        bsl::ut_check(mut_sys.bf_tls_rax().is_zero());
                    };
                };
            };
        };

        bsl::ut_scenario{"stop command, last ppid"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                syscall::bf_syscall_t mut_sys{};
                constexpr auto ppid{0x1_u16};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_sys.bf_tls_set_rax(bsl::to_u64(loader::CPUID_COMMAND_EAX));
                    mut_sys.bf_tls_set_rcx(bsl::to_u64(loader::CPUID_COMMAND_ECX_STOP));
                    mut_sys.bf_tls_set_ppid(ppid);
                    mut_sys.bf_tls_set_online_pps(online_pps);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(dispatch_vmexit_cpuid({}, {}, mut_sys, {}, {}));
                        bsl::ut_check(mut_sys.bf_tls_rax().is_zero());
                    };
                };
            };
        };

        bsl::ut_scenario{"report on command"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                syscall::bf_syscall_t mut_sys{};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_sys.bf_tls_set_rax(bsl::to_u64(loader::CPUID_COMMAND_EAX));
                    mut_sys.bf_tls_set_rcx(bsl::to_u64(loader::CPUID_COMMAND_ECX_REPORT_ON));
                    mut_sys.bf_tls_set_online_pps(online_pps);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(dispatch_vmexit_cpuid({}, {}, mut_sys, {}, {}));
                        bsl::ut_check(mut_sys.bf_tls_rax().is_zero());
                    };
                };
            };
        };

        bsl::ut_scenario{"report off command"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                syscall::bf_syscall_t mut_sys{};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_sys.bf_tls_set_rax(bsl::to_u64(loader::CPUID_COMMAND_EAX));
                    mut_sys.bf_tls_set_rcx(bsl::to_u64(loader::CPUID_COMMAND_ECX_REPORT_OFF));
                    mut_sys.bf_tls_set_online_pps(online_pps);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(dispatch_vmexit_cpuid({}, {}, mut_sys, {}, {}));
                        bsl::ut_check(mut_sys.bf_tls_rax().is_zero());
                    };
                };
            };
        };

        bsl::ut_scenario{"unknown command"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                syscall::bf_syscall_t mut_sys{};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_sys.bf_tls_set_rax(bsl::to_u64(loader::CPUID_COMMAND_EAX));
                    mut_sys.bf_tls_set_online_pps(online_pps);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(dispatch_vmexit_cpuid({}, {}, mut_sys, {}, {}));
                        bsl::ut_check(!mut_sys.bf_tls_rax().is_zero());
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
