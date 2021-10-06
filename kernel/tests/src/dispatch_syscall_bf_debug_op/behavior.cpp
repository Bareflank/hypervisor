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

#include "../../../src/dispatch_syscall_bf_debug_op.hpp"

#include <bf_constants.hpp>
#include <ext_pool_t.hpp>
#include <huge_pool_t.hpp>
#include <intrinsic_t.hpp>
#include <page_pool_t.hpp>
#include <tls_t.hpp>
#include <vm_pool_t.hpp>
#include <vmexit_log_t.hpp>
#include <vp_pool_t.hpp>
#include <vs_pool_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/string_view.hpp>
#include <bsl/ut.hpp>

namespace mk
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
        bsl::ut_scenario{"unknown syscall"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t const page_pool{};
                huge_pool_t const huge_pool{};
                intrinsic_t const intrinsic{};
                vm_pool_t const vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t const vs_pool{};
                ext_pool_t const ext_pool{};
                vmexit_log_t const log{};
                constexpr auto syscall{0xFFFFFFFFFFFFFFFF_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.ext_syscall = syscall.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall_bf_debug_op(
                                mut_tls,
                                page_pool,
                                huge_pool,
                                intrinsic,
                                vm_pool,
                                vp_pool,
                                vs_pool,
                                ext_pool,
                                log) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"OUT_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t const page_pool{};
                huge_pool_t const huge_pool{};
                intrinsic_t const intrinsic{};
                vm_pool_t const vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t const vs_pool{};
                ext_pool_t const ext_pool{};
                vmexit_log_t const log{};
                constexpr auto syscall{syscall::BF_DEBUG_OP_OUT_IDX_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.ext_syscall = syscall.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall_bf_debug_op(
                                mut_tls,
                                page_pool,
                                huge_pool,
                                intrinsic,
                                vm_pool,
                                vp_pool,
                                vs_pool,
                                ext_pool,
                                log) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"DUMP_VM_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t const page_pool{};
                huge_pool_t const huge_pool{};
                intrinsic_t const intrinsic{};
                vm_pool_t const vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t const vs_pool{};
                ext_pool_t const ext_pool{};
                vmexit_log_t const log{};
                constexpr auto syscall{syscall::BF_DEBUG_OP_DUMP_VM_IDX_VAL};
                constexpr auto vmid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(vmid).get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall_bf_debug_op(
                                mut_tls,
                                page_pool,
                                huge_pool,
                                intrinsic,
                                vm_pool,
                                vp_pool,
                                vs_pool,
                                ext_pool,
                                log) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"DUMP_VM_IDX_VAL bad vmid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t const page_pool{};
                huge_pool_t const huge_pool{};
                intrinsic_t const intrinsic{};
                vm_pool_t const vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t const vs_pool{};
                ext_pool_t const ext_pool{};
                vmexit_log_t const log{};
                constexpr auto syscall{syscall::BF_DEBUG_OP_DUMP_VM_IDX_VAL};
                constexpr auto vmid{syscall::BF_INVALID_ID};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(vmid).get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall_bf_debug_op(
                                mut_tls,
                                page_pool,
                                huge_pool,
                                intrinsic,
                                vm_pool,
                                vp_pool,
                                vs_pool,
                                ext_pool,
                                log) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"DUMP_VM_IDX_VAL bad vmid #2"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t const page_pool{};
                huge_pool_t const huge_pool{};
                intrinsic_t const intrinsic{};
                vm_pool_t const vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t const vs_pool{};
                ext_pool_t const ext_pool{};
                vmexit_log_t const log{};
                constexpr auto syscall{syscall::BF_DEBUG_OP_DUMP_VM_IDX_VAL};
                constexpr auto vmid{0x42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(vmid).get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall_bf_debug_op(
                                mut_tls,
                                page_pool,
                                huge_pool,
                                intrinsic,
                                vm_pool,
                                vp_pool,
                                vs_pool,
                                ext_pool,
                                log) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"DUMP_VP_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t const page_pool{};
                huge_pool_t const huge_pool{};
                intrinsic_t const intrinsic{};
                vm_pool_t const vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t const vs_pool{};
                ext_pool_t const ext_pool{};
                vmexit_log_t const log{};
                constexpr auto syscall{syscall::BF_DEBUG_OP_DUMP_VP_IDX_VAL};
                constexpr auto vpid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(vpid).get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall_bf_debug_op(
                                mut_tls,
                                page_pool,
                                huge_pool,
                                intrinsic,
                                vm_pool,
                                vp_pool,
                                vs_pool,
                                ext_pool,
                                log) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"DUMP_VP_IDX_VAL bad vpid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t const page_pool{};
                huge_pool_t const huge_pool{};
                intrinsic_t const intrinsic{};
                vm_pool_t const vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t const vs_pool{};
                ext_pool_t const ext_pool{};
                vmexit_log_t const log{};
                constexpr auto syscall{syscall::BF_DEBUG_OP_DUMP_VP_IDX_VAL};
                constexpr auto vpid{syscall::BF_INVALID_ID};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(vpid).get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall_bf_debug_op(
                                mut_tls,
                                page_pool,
                                huge_pool,
                                intrinsic,
                                vm_pool,
                                vp_pool,
                                vs_pool,
                                ext_pool,
                                log) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"DUMP_VP_IDX_VAL bad vpid #2"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t const page_pool{};
                huge_pool_t const huge_pool{};
                intrinsic_t const intrinsic{};
                vm_pool_t const vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t const vs_pool{};
                ext_pool_t const ext_pool{};
                vmexit_log_t const log{};
                constexpr auto syscall{syscall::BF_DEBUG_OP_DUMP_VP_IDX_VAL};
                constexpr auto vpid{0x42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(vpid).get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall_bf_debug_op(
                                mut_tls,
                                page_pool,
                                huge_pool,
                                intrinsic,
                                vm_pool,
                                vp_pool,
                                vs_pool,
                                ext_pool,
                                log) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"DUMP_VS_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t const page_pool{};
                huge_pool_t const huge_pool{};
                intrinsic_t const intrinsic{};
                vm_pool_t const vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t const vs_pool{};
                ext_pool_t const ext_pool{};
                vmexit_log_t const log{};
                constexpr auto syscall{syscall::BF_DEBUG_OP_DUMP_VS_IDX_VAL};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(vsid).get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall_bf_debug_op(
                                mut_tls,
                                page_pool,
                                huge_pool,
                                intrinsic,
                                vm_pool,
                                vp_pool,
                                vs_pool,
                                ext_pool,
                                log) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"DUMP_VS_IDX_VAL bad vsid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t const page_pool{};
                huge_pool_t const huge_pool{};
                intrinsic_t const intrinsic{};
                vm_pool_t const vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t const vs_pool{};
                ext_pool_t const ext_pool{};
                vmexit_log_t const log{};
                constexpr auto syscall{syscall::BF_DEBUG_OP_DUMP_VS_IDX_VAL};
                constexpr auto vsid{syscall::BF_INVALID_ID};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(vsid).get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall_bf_debug_op(
                                mut_tls,
                                page_pool,
                                huge_pool,
                                intrinsic,
                                vm_pool,
                                vp_pool,
                                vs_pool,
                                ext_pool,
                                log) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"DUMP_VS_IDX_VAL bad vsid #2"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t const page_pool{};
                huge_pool_t const huge_pool{};
                intrinsic_t const intrinsic{};
                vm_pool_t const vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t const vs_pool{};
                ext_pool_t const ext_pool{};
                vmexit_log_t const log{};
                constexpr auto syscall{syscall::BF_DEBUG_OP_DUMP_VS_IDX_VAL};
                constexpr auto vsid{0x42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(vsid).get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall_bf_debug_op(
                                mut_tls,
                                page_pool,
                                huge_pool,
                                intrinsic,
                                vm_pool,
                                vp_pool,
                                vs_pool,
                                ext_pool,
                                log) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"DUMP_VMEXIT_LOG_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t const page_pool{};
                huge_pool_t const huge_pool{};
                intrinsic_t const intrinsic{};
                vm_pool_t const vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t const vs_pool{};
                ext_pool_t const ext_pool{};
                vmexit_log_t const log{};
                constexpr auto syscall{syscall::BF_DEBUG_OP_DUMP_VMEXIT_LOG_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto ppid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = online_pps.get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(ppid).get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall_bf_debug_op(
                                mut_tls,
                                page_pool,
                                huge_pool,
                                intrinsic,
                                vm_pool,
                                vp_pool,
                                vs_pool,
                                ext_pool,
                                log) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"DUMP_VMEXIT_LOG_IDX_VAL invalid ppid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t const page_pool{};
                huge_pool_t const huge_pool{};
                intrinsic_t const intrinsic{};
                vm_pool_t const vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t const vs_pool{};
                ext_pool_t const ext_pool{};
                vmexit_log_t const log{};
                constexpr auto syscall{syscall::BF_DEBUG_OP_DUMP_VMEXIT_LOG_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto ppid{syscall::BF_INVALID_ID};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = online_pps.get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(ppid).get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall_bf_debug_op(
                                mut_tls,
                                page_pool,
                                huge_pool,
                                intrinsic,
                                vm_pool,
                                vp_pool,
                                vs_pool,
                                ext_pool,
                                log) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"DUMP_VMEXIT_LOG_IDX_VAL invalid ppid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t const page_pool{};
                huge_pool_t const huge_pool{};
                intrinsic_t const intrinsic{};
                vm_pool_t const vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t const vs_pool{};
                ext_pool_t const ext_pool{};
                vmexit_log_t const log{};
                constexpr auto syscall{syscall::BF_DEBUG_OP_DUMP_VMEXIT_LOG_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto ppid{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = online_pps.get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(ppid).get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall_bf_debug_op(
                                mut_tls,
                                page_pool,
                                huge_pool,
                                intrinsic,
                                vm_pool,
                                vp_pool,
                                vs_pool,
                                ext_pool,
                                log) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"DUMP_VMEXIT_LOG_IDX_VAL invalid ppid #3"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t const page_pool{};
                huge_pool_t const huge_pool{};
                intrinsic_t const intrinsic{};
                vm_pool_t const vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t const vs_pool{};
                ext_pool_t const ext_pool{};
                vmexit_log_t const log{};
                constexpr auto syscall{syscall::BF_DEBUG_OP_DUMP_VMEXIT_LOG_IDX_VAL};
                constexpr auto online_pps{0x0_u16};
                constexpr auto ppid{0x1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = online_pps.get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(ppid).get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall_bf_debug_op(
                                mut_tls,
                                page_pool,
                                huge_pool,
                                intrinsic,
                                vm_pool,
                                vp_pool,
                                vs_pool,
                                ext_pool,
                                log) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"WRITE_C_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t const page_pool{};
                huge_pool_t const huge_pool{};
                intrinsic_t const intrinsic{};
                vm_pool_t const vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t const vs_pool{};
                ext_pool_t const ext_pool{};
                vmexit_log_t const log{};
                constexpr auto syscall{syscall::BF_DEBUG_OP_WRITE_C_IDX_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.ext_syscall = syscall.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall_bf_debug_op(
                                mut_tls,
                                page_pool,
                                huge_pool,
                                intrinsic,
                                vm_pool,
                                vp_pool,
                                vs_pool,
                                ext_pool,
                                log) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"WRITE_STR_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given_at_runtime{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t const page_pool{};
                huge_pool_t const huge_pool{};
                intrinsic_t const intrinsic{};
                vm_pool_t const vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t const vs_pool{};
                ext_pool_t const ext_pool{};
                vmexit_log_t const log{};
                constexpr auto syscall{syscall::BF_DEBUG_OP_WRITE_STR_IDX_VAL};
                bsl::string_view const msg{"the cow is blue for this is true\n"};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.ext_syscall = syscall.get();
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                    mut_tls.ext_reg0 = reinterpret_cast<bsl::uint64>(msg.data());
                    mut_tls.ext_reg1 = msg.size().get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall_bf_debug_op(
                                mut_tls,
                                page_pool,
                                huge_pool,
                                intrinsic,
                                vm_pool,
                                vp_pool,
                                vs_pool,
                                ext_pool,
                                log) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"WRITE_STR_IDX_VAL invalid size"} = [&]() noexcept {
            bsl::ut_given_at_runtime{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t const page_pool{};
                huge_pool_t const huge_pool{};
                intrinsic_t const intrinsic{};
                vm_pool_t const vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t const vs_pool{};
                ext_pool_t const ext_pool{};
                vmexit_log_t const log{};
                constexpr auto syscall{syscall::BF_DEBUG_OP_WRITE_STR_IDX_VAL};
                bsl::string_view const msg{"the cow is blue for this is true\n"};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.ext_syscall = syscall.get();
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                    mut_tls.ext_reg0 = reinterpret_cast<bsl::uint64>(msg.data());
                    mut_tls.ext_reg1 = bsl::safe_umx::max_value().get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall_bf_debug_op(
                                mut_tls,
                                page_pool,
                                huge_pool,
                                intrinsic,
                                vm_pool,
                                vp_pool,
                                vs_pool,
                                ext_pool,
                                log) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"WRITE_STR_IDX_VAL smaller size"} = [&]() noexcept {
            bsl::ut_given_at_runtime{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t const page_pool{};
                huge_pool_t const huge_pool{};
                intrinsic_t const intrinsic{};
                vm_pool_t const vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t const vs_pool{};
                ext_pool_t const ext_pool{};
                vmexit_log_t const log{};
                constexpr auto syscall{syscall::BF_DEBUG_OP_WRITE_STR_IDX_VAL};
                bsl::string_view const msg{"the cow is blue for this is true\n"};
                constexpr auto size{15_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.ext_syscall = syscall.get();
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                    mut_tls.ext_reg0 = reinterpret_cast<bsl::uint64>(msg.data());
                    mut_tls.ext_reg1 = size.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall_bf_debug_op(
                                mut_tls,
                                page_pool,
                                huge_pool,
                                intrinsic,
                                vm_pool,
                                vp_pool,
                                vs_pool,
                                ext_pool,
                                log) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"DUMP_EXT_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t const page_pool{};
                huge_pool_t const huge_pool{};
                intrinsic_t const intrinsic{};
                vm_pool_t const vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t const vs_pool{};
                ext_pool_t const ext_pool{};
                vmexit_log_t const log{};
                constexpr auto syscall{syscall::BF_DEBUG_OP_DUMP_EXT_IDX_VAL};
                constexpr auto extid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(extid).get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall_bf_debug_op(
                                mut_tls,
                                page_pool,
                                huge_pool,
                                intrinsic,
                                vm_pool,
                                vp_pool,
                                vs_pool,
                                ext_pool,
                                log) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"DUMP_EXT_IDX_VAL invalid extid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t const page_pool{};
                huge_pool_t const huge_pool{};
                intrinsic_t const intrinsic{};
                vm_pool_t const vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t const vs_pool{};
                ext_pool_t const ext_pool{};
                vmexit_log_t const log{};
                constexpr auto syscall{syscall::BF_DEBUG_OP_DUMP_EXT_IDX_VAL};
                constexpr auto extid{syscall::BF_INVALID_ID};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(extid).get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall_bf_debug_op(
                                mut_tls,
                                page_pool,
                                huge_pool,
                                intrinsic,
                                vm_pool,
                                vp_pool,
                                vs_pool,
                                ext_pool,
                                log) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"DUMP_EXT_IDX_VAL invalid extid #2"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t const page_pool{};
                huge_pool_t const huge_pool{};
                intrinsic_t const intrinsic{};
                vm_pool_t const vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t const vs_pool{};
                ext_pool_t const ext_pool{};
                vmexit_log_t const log{};
                constexpr auto syscall{syscall::BF_DEBUG_OP_DUMP_EXT_IDX_VAL};
                constexpr auto extid{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(extid).get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall_bf_debug_op(
                                mut_tls,
                                page_pool,
                                huge_pool,
                                intrinsic,
                                vm_pool,
                                vp_pool,
                                vs_pool,
                                ext_pool,
                                log) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"DUMP_PAGE_POOL_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t const page_pool{};
                huge_pool_t const huge_pool{};
                intrinsic_t const intrinsic{};
                vm_pool_t const vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t const vs_pool{};
                ext_pool_t const ext_pool{};
                vmexit_log_t const log{};
                constexpr auto syscall{syscall::BF_DEBUG_OP_DUMP_PAGE_POOL_IDX_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.ext_syscall = syscall.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall_bf_debug_op(
                                mut_tls,
                                page_pool,
                                huge_pool,
                                intrinsic,
                                vm_pool,
                                vp_pool,
                                vs_pool,
                                ext_pool,
                                log) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"DUMP_HUGE_POOL_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t const page_pool{};
                huge_pool_t const huge_pool{};
                intrinsic_t const intrinsic{};
                vm_pool_t const vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t const vs_pool{};
                ext_pool_t const ext_pool{};
                vmexit_log_t const log{};
                constexpr auto syscall{syscall::BF_DEBUG_OP_DUMP_HUGE_POOL_IDX_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.ext_syscall = syscall.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall_bf_debug_op(
                                mut_tls,
                                page_pool,
                                huge_pool,
                                intrinsic,
                                vm_pool,
                                vp_pool,
                                vs_pool,
                                ext_pool,
                                log) == syscall::BF_STATUS_SUCCESS);
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
