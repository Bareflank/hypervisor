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

#include "../../../../../src/x64/amd/vmexit_t.hpp"

#include <bsl/ut.hpp>

namespace example
{
    // -------------------------------------------------------------------------
    // constants
    // -------------------------------------------------------------------------

    /// @brief stores the answer to all things (in 32 bits)
    constexpr auto ANSWER32{42_u32};

    // -------------------------------------------------------------------------
    // tests
    // -------------------------------------------------------------------------

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
        bsl::ut_scenario{"initialize success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmexit_t vmexit{};
                gs_t gs{};
                tls_t tls{};
                syscall::bf_syscall_t sys{};
                intrinsic_t intrinsic{};
                vp_pool_t vp_pool{};
                vps_pool_t vps_pool{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(vmexit.initialize(gs, tls, sys, intrinsic, vp_pool, vps_pool));
                };
            };
        };

        bsl::ut_scenario{"release executes without initialize"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmexit_t vmexit{};
                gs_t gs{};
                tls_t tls{};
                syscall::bf_syscall_t sys{};
                intrinsic_t intrinsic{};
                vp_pool_t vp_pool{};
                vps_pool_t vps_pool{};
                bsl::ut_then{} = [&]() noexcept {
                    vmexit.release(gs, tls, sys, intrinsic, vp_pool, vps_pool);
                };
            };
        };

        bsl::ut_scenario{"release executes with initialize"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmexit_t vmexit{};
                gs_t gs{};
                tls_t tls{};
                syscall::bf_syscall_t sys{};
                intrinsic_t intrinsic{};
                vp_pool_t vp_pool{};
                vps_pool_t vps_pool{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(
                        vmexit.initialize(gs, tls, sys, intrinsic, vp_pool, vps_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        vmexit.release(gs, tls, sys, intrinsic, vp_pool, vps_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"dispatch cpuid stop"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmexit_t vmexit{};
                gs_t gs{};
                tls_t tls{};
                syscall::bf_syscall_t sys{};
                intrinsic_t intrinsic{};
                vp_pool_t vp_pool{};
                vps_pool_t vps_pool{};
                constexpr auto exit_reason{0x72_u64};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(
                        vmexit.initialize(gs, tls, sys, intrinsic, vp_pool, vps_pool));
                    sys.bf_tls_set_rax(bsl::to_u64(loader::CPUID_COMMAND_EAX));
                    sys.bf_tls_set_rcx(bsl::to_u64(loader::CPUID_COMMAND_ECX_STOP));
                    sys.bf_tls_set_online_pps(online_pps);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(vmexit.dispatch(
                            gs, tls, sys, intrinsic, vp_pool, vps_pool, {}, exit_reason));
                    };
                };
            };
        };

        bsl::ut_scenario{"dispatch cpuid stop last ppid"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmexit_t vmexit{};
                gs_t gs{};
                tls_t tls{};
                syscall::bf_syscall_t sys{};
                intrinsic_t intrinsic{};
                vp_pool_t vp_pool{};
                vps_pool_t vps_pool{};
                constexpr auto exit_reason{0x72_u64};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(
                        vmexit.initialize(gs, tls, sys, intrinsic, vp_pool, vps_pool));
                    sys.bf_tls_set_rax(bsl::to_u64(loader::CPUID_COMMAND_EAX));
                    sys.bf_tls_set_rcx(bsl::to_u64(loader::CPUID_COMMAND_ECX_STOP));
                    sys.bf_tls_set_ppid(online_pps - 1_u16);
                    sys.bf_tls_set_online_pps(online_pps);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(vmexit.dispatch(
                            gs, tls, sys, intrinsic, vp_pool, vps_pool, {}, exit_reason));
                    };
                };
            };
        };

        bsl::ut_scenario{"dispatch cpuid stop bf_vps_op_advance_ip fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmexit_t vmexit{};
                gs_t gs{};
                tls_t tls{};
                syscall::bf_syscall_t sys{};
                intrinsic_t intrinsic{};
                vp_pool_t vp_pool{};
                vps_pool_t vps_pool{};
                constexpr auto exit_reason{0x72_u64};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(
                        vmexit.initialize(gs, tls, sys, intrinsic, vp_pool, vps_pool));
                    sys.bf_tls_set_rax(bsl::to_u64(loader::CPUID_COMMAND_EAX));
                    sys.bf_tls_set_rcx(bsl::to_u64(loader::CPUID_COMMAND_ECX_STOP));
                    sys.bf_tls_set_online_pps(online_pps);
                    sys.set_bf_vps_op_advance_ip({}, bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!vmexit.dispatch(
                            gs, tls, sys, intrinsic, vp_pool, vps_pool, {}, exit_reason));
                    };
                };
            };
        };

        bsl::ut_scenario{"dispatch report on"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmexit_t vmexit{};
                gs_t gs{};
                tls_t tls{};
                syscall::bf_syscall_t sys{};
                intrinsic_t intrinsic{};
                vp_pool_t vp_pool{};
                vps_pool_t vps_pool{};
                constexpr auto exit_reason{0x72_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(
                        vmexit.initialize(gs, tls, sys, intrinsic, vp_pool, vps_pool));
                    sys.bf_tls_set_rax(bsl::to_u64(loader::CPUID_COMMAND_EAX));
                    sys.bf_tls_set_rcx(bsl::to_u64(loader::CPUID_COMMAND_ECX_REPORT_ON));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(vmexit.dispatch(
                            gs, tls, sys, intrinsic, vp_pool, vps_pool, {}, exit_reason));
                    };
                };
            };
        };

        bsl::ut_scenario{"dispatch report off"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmexit_t vmexit{};
                gs_t gs{};
                tls_t tls{};
                syscall::bf_syscall_t sys{};
                intrinsic_t intrinsic{};
                vp_pool_t vp_pool{};
                vps_pool_t vps_pool{};
                constexpr auto exit_reason{0x72_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(
                        vmexit.initialize(gs, tls, sys, intrinsic, vp_pool, vps_pool));
                    sys.bf_tls_set_rax(bsl::to_u64(loader::CPUID_COMMAND_EAX));
                    sys.bf_tls_set_rcx(bsl::to_u64(loader::CPUID_COMMAND_ECX_REPORT_OFF));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(vmexit.dispatch(
                            gs, tls, sys, intrinsic, vp_pool, vps_pool, {}, exit_reason));
                    };
                };
            };
        };

        bsl::ut_scenario{"dispatch cpuid default"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmexit_t vmexit{};
                gs_t gs{};
                tls_t tls{};
                syscall::bf_syscall_t sys{};
                intrinsic_t intrinsic{};
                vp_pool_t vp_pool{};
                vps_pool_t vps_pool{};
                constexpr auto exit_reason{0x72_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(
                        vmexit.initialize(gs, tls, sys, intrinsic, vp_pool, vps_pool));
                    intrinsic.set_cpuid(ANSWER32, ANSWER32, ANSWER32, ANSWER32);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(vmexit.dispatch(
                            gs, tls, sys, intrinsic, vp_pool, vps_pool, {}, exit_reason));
                        bsl::ut_check(sys.bf_tls_rax() == bsl::to_u64(ANSWER32));
                        bsl::ut_check(sys.bf_tls_rbx() == bsl::to_u64(ANSWER32));
                        bsl::ut_check(sys.bf_tls_rcx() == bsl::to_u64(ANSWER32));
                        bsl::ut_check(sys.bf_tls_rdx() == bsl::to_u64(ANSWER32));
                    };
                };
            };
        };

        bsl::ut_scenario{"dispatch invalid command"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmexit_t vmexit{};
                gs_t gs{};
                tls_t tls{};
                syscall::bf_syscall_t sys{};
                intrinsic_t intrinsic{};
                vp_pool_t vp_pool{};
                vps_pool_t vps_pool{};
                constexpr auto exit_reason{0x72_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(
                        vmexit.initialize(gs, tls, sys, intrinsic, vp_pool, vps_pool));
                    sys.bf_tls_set_rax(bsl::to_u64(loader::CPUID_COMMAND_EAX));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(vmexit.dispatch(
                            gs, tls, sys, intrinsic, vp_pool, vps_pool, {}, exit_reason));
                    };
                };
            };
        };

        bsl::ut_scenario{"dispatch fails by default"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmexit_t vmexit{};
                gs_t gs{};
                tls_t tls{};
                syscall::bf_syscall_t sys{};
                intrinsic_t intrinsic{};
                vp_pool_t vp_pool{};
                vps_pool_t vps_pool{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(
                        vmexit.initialize(gs, tls, sys, intrinsic, vp_pool, vps_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !vmexit.dispatch(gs, tls, sys, intrinsic, vp_pool, vps_pool, {}, {}));
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
