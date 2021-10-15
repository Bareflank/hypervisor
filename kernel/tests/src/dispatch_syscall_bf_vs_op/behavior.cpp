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

#include "../../../src/dispatch_syscall_bf_vs_op.hpp"

#include <bf_constants.hpp>
#include <bf_reg_t.hpp>
#include <ext_pool_t.hpp>
#include <ext_t.hpp>
#include <intrinsic_t.hpp>
#include <page_pool_t.hpp>
#include <tls_t.hpp>
#include <vm_pool_t.hpp>
#include <vp_pool_t.hpp>
#include <vs_pool_t.hpp>
#include <vs_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
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
        bsl::ut_scenario{"invalid_handle"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"unknown syscall"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{0xFFFFFFFFFFFFFFFF_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"wrong extension"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{0xFFFFFFFFFFFFFFFF_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"CREATE_VS_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_CREATE_VS_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"CREATE_VS_IDX_VAL invalid vpid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_CREATE_VS_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vpid{syscall::BF_INVALID_ID};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vpid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"CREATE_VS_IDX_VAL invalid vpid #2"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_CREATE_VS_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vpid{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vpid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"CREATE_VS_IDX_VAL vpid never allocated"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_CREATE_VS_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"CREATE_VS_IDX_VAL invalid ppid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_CREATE_VS_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto ppid{syscall::BF_INVALID_ID};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = bsl::to_u64(ppid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"CREATE_VS_IDX_VAL invalid ppid #2"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_CREATE_VS_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto ppid{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = bsl::to_u64(ppid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"CREATE_VS_IDX_VAL invalid ppid #3"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_CREATE_VS_IDX_VAL};
                constexpr auto online_pps{0x1_u16};
                constexpr auto ppid{0x1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = bsl::to_u64(ppid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"CREATE_VS_IDX_VAL allocate too many"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_CREATE_VS_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    auto const hndl{mut_ext.open_handle()};

                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(hndl).get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) == syscall::BF_STATUS_SUCCESS);
                    };

                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(hndl).get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) == syscall::BF_STATUS_SUCCESS);
                    };

                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(hndl).get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"DESTROY_VS_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_DESTROY_VS_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"DESTROY_VS_IDX_VAL invalid vsid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_DESTROY_VS_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vsid{syscall::BF_INVALID_ID};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vsid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"DESTROY_VS_IDX_VAL invalid vsid #2"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_DESTROY_VS_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vsid{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vsid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"DESTROY_VS_IDX_VAL vsid never allocated"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_DESTROY_VS_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"DESTROY_VS_IDX_VAL still active"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_DESTROY_VS_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    mut_vs_pool.set_active(mut_tls, mut_intrinsic, {});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"INIT_AS_ROOT_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_INIT_AS_ROOT_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"INIT_AS_ROOT_IDX_VAL invalid vsid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_INIT_AS_ROOT_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vsid{syscall::BF_INVALID_ID};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vsid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"INIT_AS_ROOT_IDX_VAL invalid vsid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_INIT_AS_ROOT_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vsid{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vsid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"INIT_AS_ROOT_IDX_VAL vsid never allocated"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_INIT_AS_ROOT_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"INIT_AS_ROOT_IDX_VAL from a different pp"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_INIT_AS_ROOT_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto ppid{0x1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, ppid));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"INIT_AS_ROOT_IDX_VAL not a root vs"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_INIT_AS_ROOT_IDX_VAL};
                constexpr auto online_pps{0x1_u16};
                constexpr auto vsid{0x1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vsid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"READ_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_READ_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto reg{syscall::bf_reg_t::bf_reg_t_dummy};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = static_cast<bsl::uint64>(reg);
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"READ_IDX_VAL invalid vsid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_READ_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vsid{syscall::BF_INVALID_ID};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vsid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"READ_IDX_VAL invalid vsid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_READ_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vsid{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vsid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"READ_IDX_VAL vsid never allocated"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_READ_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"READ_IDX_VAL from a different pp"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_READ_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto ppid{0x1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, ppid));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"READ_IDX_VAL invalid reg #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_READ_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto reg{syscall::bf_reg_t::bf_reg_t_unsupported};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = static_cast<bsl::uint64>(reg);
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"READ_IDX_VAL invalid reg #2"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_READ_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto reg{syscall::bf_reg_t::bf_reg_t_invalid};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = static_cast<bsl::uint64>(reg);
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"READ_IDX_VAL invalid reg #3"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_READ_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto reg{static_cast<syscall::bf_reg_t>(42)};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = static_cast<bsl::uint64>(reg);
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"READ_IDX_VAL read fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_READ_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto reg{syscall::bf_reg_t::bf_reg_t_dummy};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = static_cast<bsl::uint64>(reg);
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    mut_tls.test_ret = UNIT_TEST_VS_FAIL_READ;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"WRITE_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_WRITE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto reg{syscall::bf_reg_t::bf_reg_t_dummy};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = static_cast<bsl::uint64>(reg);
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"WRITE_IDX_VAL invalid vsid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_WRITE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vsid{syscall::BF_INVALID_ID};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vsid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"WRITE_IDX_VAL invalid vsid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_WRITE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vsid{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vsid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"WRITE_IDX_VAL vsid never allocated"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_WRITE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"WRITE_IDX_VAL from a different pp"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_WRITE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto ppid{0x1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, ppid));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"WRITE_IDX_VAL invalid reg #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_WRITE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto reg{syscall::bf_reg_t::bf_reg_t_unsupported};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = static_cast<bsl::uint64>(reg);
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"WRITE_IDX_VAL invalid reg #2"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_WRITE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto reg{syscall::bf_reg_t::bf_reg_t_invalid};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = static_cast<bsl::uint64>(reg);
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"WRITE_IDX_VAL invalid reg #3"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_WRITE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto reg{static_cast<syscall::bf_reg_t>(42)};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = static_cast<bsl::uint64>(reg);
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"WRITE_IDX_VAL read fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_WRITE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto reg{syscall::bf_reg_t::bf_reg_t_dummy};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = static_cast<bsl::uint64>(reg);
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    mut_tls.test_ret = UNIT_TEST_VS_FAIL_WRITE;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"RUN_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"RUN_IDX_VAL already active"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.set_active(mut_tls, {});
                    mut_vp_pool.set_active(mut_tls, {});
                    mut_vs_pool.set_active(mut_tls, mut_intrinsic, {});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"RUN_IDX_VAL invalid vmid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{syscall::BF_INVALID_ID};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"RUN_IDX_VAL invalid vmid #2"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{42_u16};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"RUN_IDX_VAL vmid never allocated"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x0_u16};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"RUN_IDX_VAL invalid vpid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x0_u16};
                constexpr auto vpid{syscall::BF_INVALID_ID};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"RUN_IDX_VAL invalid vpid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x0_u16};
                constexpr auto vpid{42_u16};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"RUN_IDX_VAL vpid never allocated"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x0_u16};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"RUN_IDX_VAL invalid vsid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x0_u16};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{syscall::BF_INVALID_ID};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"RUN_IDX_VAL invalid vsid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x0_u16};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"RUN_IDX_VAL vsid never allocated"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x0_u16};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"RUN_IDX_VAL non local vsid"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x0_u16};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{0x0_u16};
                constexpr auto ppid{0x1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, ppid));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"RUN_IDX_VAL vp assigned to wrong vm"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x1_u16};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, vmid));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"RUN_IDX_VAL vp assigned to wrong vm"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x1_u16};
                constexpr auto vpid{0x1_u16};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, vmid));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, vpid, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"RUN_IDX_VAL vpid active on another core"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                tls_t mut_tls_remote{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto ppid{0x1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    mut_tls_remote.ppid = ppid.get();
                    mut_tls_remote.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_vp_pool.set_active(mut_tls_remote, {});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"RUN_IDX_VAL vsid active on another core"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                tls_t mut_tls_remote{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto ppid{0x1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    mut_tls_remote.ppid = ppid.get();
                    mut_tls_remote.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vs_pool.set_active(mut_tls_remote, mut_intrinsic, {});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"RUN_CURRENT_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_RUN_CURRENT_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"RUN_CURRENT_IDX_VAL active vmid"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_RUN_CURRENT_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"RUN_CURRENT_IDX_VAL active vpid"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_RUN_CURRENT_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"RUN_CURRENT_IDX_VAL active vsid"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_RUN_CURRENT_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ADVANCE_IP_AND_RUN_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ADVANCE_IP_AND_RUN_IDX_VAL already active"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.set_active(mut_tls, {});
                    mut_vp_pool.set_active(mut_tls, {});
                    mut_vs_pool.set_active(mut_tls, mut_intrinsic, {});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ADVANCE_IP_AND_RUN_IDX_VAL invalid vmid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{syscall::BF_INVALID_ID};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ADVANCE_IP_AND_RUN_IDX_VAL invalid vmid #2"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{42_u16};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ADVANCE_IP_AND_RUN_IDX_VAL vmid never allocated"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x0_u16};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ADVANCE_IP_AND_RUN_IDX_VAL invalid vpid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x0_u16};
                constexpr auto vpid{syscall::BF_INVALID_ID};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ADVANCE_IP_AND_RUN_IDX_VAL invalid vpid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x0_u16};
                constexpr auto vpid{42_u16};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ADVANCE_IP_AND_RUN_IDX_VAL vpid never allocated"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x0_u16};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ADVANCE_IP_AND_RUN_IDX_VAL invalid vsid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x0_u16};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{syscall::BF_INVALID_ID};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ADVANCE_IP_AND_RUN_IDX_VAL invalid vsid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x0_u16};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ADVANCE_IP_AND_RUN_IDX_VAL vsid never allocated"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x0_u16};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ADVANCE_IP_AND_RUN_IDX_VAL non local vsid"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x0_u16};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{0x0_u16};
                constexpr auto ppid{0x1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, ppid));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ADVANCE_IP_AND_RUN_IDX_VAL vp assigned to wrong vm"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x1_u16};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, vmid));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ADVANCE_IP_AND_RUN_IDX_VAL vp assigned to wrong vm"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x1_u16};
                constexpr auto vpid{0x1_u16};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, vmid));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, vpid, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{
            "ADVANCE_IP_AND_RUN_IDX_VAL vpid active on another core"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                tls_t mut_tls_remote{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto ppid{0x1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    mut_tls_remote.ppid = ppid.get();
                    mut_tls_remote.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_vp_pool.set_active(mut_tls_remote, {});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{
            "ADVANCE_IP_AND_RUN_IDX_VAL vsid active on another core"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                tls_t mut_tls_remote{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_RUN_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto ppid{0x1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    mut_tls_remote.ppid = ppid.get();
                    mut_tls_remote.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vs_pool.set_active(mut_tls_remote, mut_intrinsic, {});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ADVANCE_IP_AND_RUN_CURRENT_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_RUN_CURRENT_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ADVANCE_IP_AND_RUN_CURRENT_IDX_VAL not active yet"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_RUN_CURRENT_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"PROMOTE_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_PROMOTE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"PROMOTE_IDX_VAL invalid vsid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_PROMOTE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vsid{syscall::BF_INVALID_ID};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vsid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"PROMOTE_IDX_VAL invalid vsid #2"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_PROMOTE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vsid{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vsid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"PROMOTE_IDX_VAL vsid never allocated"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_PROMOTE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"PROMOTE_IDX_VAL not locally assigned"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_PROMOTE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto ppid{0x1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, ppid));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"CLEAR_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_CLEAR_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"CLEAR_IDX_VAL invalid vsid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_CLEAR_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vsid{syscall::BF_INVALID_ID};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vsid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"CLEAR_IDX_VAL invalid vsid #2"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_CLEAR_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vsid{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vsid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"CLEAR_IDX_VAL vsid never allocated"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_CLEAR_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"CLEAR_IDX_VAL not locally assigned"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_CLEAR_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto ppid{0x1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, ppid));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"MIGRATE_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_MIGRATE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"MIGRATE_IDX_VAL invalid vsid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_MIGRATE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vsid{syscall::BF_INVALID_ID};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vsid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"MIGRATE_IDX_VAL invalid vsid #2"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_MIGRATE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vsid{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vsid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"MIGRATE_IDX_VAL vsid never allocated"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_MIGRATE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"MIGRATE_IDX_VAL invalid ppid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_MIGRATE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto ppid{syscall::BF_INVALID_ID};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = bsl::to_u64(ppid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"MIGRATE_IDX_VAL invalid ppid #2"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_MIGRATE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto ppid{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = bsl::to_u64(ppid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"MIGRATE_IDX_VAL invalid ppid #3"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_MIGRATE_IDX_VAL};
                constexpr auto online_pps{0x1_u16};
                constexpr auto ppid{0x1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = bsl::to_u64(ppid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"MIGRATE_IDX_VAL not already assigned to pp"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_MIGRATE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto ppid{0x1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = bsl::to_u64(ppid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"MIGRATE_IDX_VAL active on another pp"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                tls_t mut_tls_remote{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_MIGRATE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto ppid{0x1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = bsl::to_u64(ppid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    mut_tls_remote.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls_remote.ppid = bsl::to_u16(ppid).get();
                    mut_tls_remote.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vs_pool.set_active(mut_tls_remote, mut_intrinsic, {});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"SET_ACTIVE_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_SET_ACTIVE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"SET_ACTIVE_IDX_VAL already active"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_SET_ACTIVE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.set_active(mut_tls, {});
                    mut_vp_pool.set_active(mut_tls, {});
                    mut_vs_pool.set_active(mut_tls, mut_intrinsic, {});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"SET_ACTIVE_IDX_VAL invalid vmid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_SET_ACTIVE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{syscall::BF_INVALID_ID};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"SET_ACTIVE_IDX_VAL invalid vmid #2"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_SET_ACTIVE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{42_u16};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"SET_ACTIVE_IDX_VAL vmid never allocated"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_SET_ACTIVE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x0_u16};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"SET_ACTIVE_IDX_VAL invalid vpid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_SET_ACTIVE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x0_u16};
                constexpr auto vpid{syscall::BF_INVALID_ID};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"SET_ACTIVE_IDX_VAL invalid vpid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_SET_ACTIVE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x0_u16};
                constexpr auto vpid{42_u16};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"SET_ACTIVE_IDX_VAL vpid never allocated"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_SET_ACTIVE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x0_u16};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"SET_ACTIVE_IDX_VAL invalid vsid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_SET_ACTIVE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x0_u16};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{syscall::BF_INVALID_ID};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"SET_ACTIVE_IDX_VAL invalid vsid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_SET_ACTIVE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x0_u16};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"SET_ACTIVE_IDX_VAL vsid never allocated"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_SET_ACTIVE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x0_u16};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"SET_ACTIVE_IDX_VAL non local vsid"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_SET_ACTIVE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x0_u16};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{0x0_u16};
                constexpr auto ppid{0x1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, ppid));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"SET_ACTIVE_IDX_VAL vp assigned to wrong vm"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_SET_ACTIVE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x1_u16};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, vmid));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"SET_ACTIVE_IDX_VAL vp assigned to wrong vm"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_SET_ACTIVE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x1_u16};
                constexpr auto vpid{0x1_u16};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, vmid));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, vpid, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"SET_ACTIVE_IDX_VAL vpid active on another core"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                tls_t mut_tls_remote{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_SET_ACTIVE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto ppid{0x1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    mut_tls_remote.ppid = ppid.get();
                    mut_tls_remote.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_vp_pool.set_active(mut_tls_remote, {});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"SET_ACTIVE_IDX_VAL vsid active on another core"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                tls_t mut_tls_remote{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_SET_ACTIVE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto ppid{0x1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    mut_tls_remote.ppid = ppid.get();
                    mut_tls_remote.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vs_pool.set_active(mut_tls_remote, mut_intrinsic, {});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL already active"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    mut_vm_pool.set_active(mut_tls, {});
                    mut_vp_pool.set_active(mut_tls, {});
                    mut_vs_pool.set_active(mut_tls, mut_intrinsic, {});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL invalid vmid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{syscall::BF_INVALID_ID};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL invalid vmid #2"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{42_u16};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL vmid never allocated"} =
            [&]() noexcept {
                bsl::ut_given{} = [&]() noexcept {
                    tls_t mut_tls{};
                    page_pool_t mut_page_pool{};
                    intrinsic_t mut_intrinsic{};
                    vm_pool_t mut_vm_pool{};
                    vp_pool_t mut_vp_pool{};
                    vs_pool_t mut_vs_pool{};
                    ext_pool_t mut_ext_pool{};
                    ext_t mut_ext{};
                    constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL};
                    constexpr auto online_pps{0x2_u16};
                    constexpr auto vmid{0x0_u16};
                    constexpr auto vpid{0x0_u16};
                    constexpr auto vsid{0x0_u16};
                    bsl::ut_when{} = [&]() noexcept {
                        bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                        mut_tls.ext = &mut_ext;
                        mut_tls.ext_vmexit = &mut_ext;
                        mut_tls.online_pps = bsl::to_u16(online_pps).get();
                        mut_tls.ext_syscall = syscall.get();
                        mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                        mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                        mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                        mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                        mut_vm_pool.initialize();
                        mut_vp_pool.initialize();
                        mut_vs_pool.initialize();
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(
                                dispatch_syscall_bf_vs_op(
                                    mut_tls,
                                    mut_page_pool,
                                    mut_intrinsic,
                                    mut_vm_pool,
                                    mut_vp_pool,
                                    mut_vs_pool,
                                    mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                        };
                    };
                };
            };

        bsl::ut_scenario{"ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL invalid vpid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x0_u16};
                constexpr auto vpid{syscall::BF_INVALID_ID};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL invalid vpid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x0_u16};
                constexpr auto vpid{42_u16};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL vpid never allocated"} =
            [&]() noexcept {
                bsl::ut_given{} = [&]() noexcept {
                    tls_t mut_tls{};
                    page_pool_t mut_page_pool{};
                    intrinsic_t mut_intrinsic{};
                    vm_pool_t mut_vm_pool{};
                    vp_pool_t mut_vp_pool{};
                    vs_pool_t mut_vs_pool{};
                    ext_pool_t mut_ext_pool{};
                    ext_t mut_ext{};
                    constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL};
                    constexpr auto online_pps{0x2_u16};
                    constexpr auto vmid{0x0_u16};
                    constexpr auto vpid{0x0_u16};
                    constexpr auto vsid{0x0_u16};
                    bsl::ut_when{} = [&]() noexcept {
                        bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                        mut_tls.ext = &mut_ext;
                        mut_tls.ext_vmexit = &mut_ext;
                        mut_tls.online_pps = bsl::to_u16(online_pps).get();
                        mut_tls.ext_syscall = syscall.get();
                        mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                        mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                        mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                        mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                        mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                        mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                        mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                        mut_vm_pool.initialize();
                        mut_vp_pool.initialize();
                        mut_vs_pool.initialize();
                        bsl::ut_required_step(
                            mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(
                                dispatch_syscall_bf_vs_op(
                                    mut_tls,
                                    mut_page_pool,
                                    mut_intrinsic,
                                    mut_vm_pool,
                                    mut_vp_pool,
                                    mut_vs_pool,
                                    mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                        };
                    };
                };
            };

        bsl::ut_scenario{"ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL invalid vsid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x0_u16};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{syscall::BF_INVALID_ID};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL invalid vsid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x0_u16};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL vsid never allocated"} =
            [&]() noexcept {
                bsl::ut_given{} = [&]() noexcept {
                    tls_t mut_tls{};
                    page_pool_t mut_page_pool{};
                    intrinsic_t mut_intrinsic{};
                    vm_pool_t mut_vm_pool{};
                    vp_pool_t mut_vp_pool{};
                    vs_pool_t mut_vs_pool{};
                    ext_pool_t mut_ext_pool{};
                    ext_t mut_ext{};
                    constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL};
                    constexpr auto online_pps{0x2_u16};
                    constexpr auto vmid{0x0_u16};
                    constexpr auto vpid{0x0_u16};
                    constexpr auto vsid{0x0_u16};
                    bsl::ut_when{} = [&]() noexcept {
                        bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                        mut_tls.ext = &mut_ext;
                        mut_tls.ext_vmexit = &mut_ext;
                        mut_tls.online_pps = bsl::to_u16(online_pps).get();
                        mut_tls.ext_syscall = syscall.get();
                        mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                        mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                        mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                        mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                        mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                        mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                        mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                        mut_vm_pool.initialize();
                        mut_vp_pool.initialize();
                        mut_vs_pool.initialize();
                        bsl::ut_required_step(
                            mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                        bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(
                                dispatch_syscall_bf_vs_op(
                                    mut_tls,
                                    mut_page_pool,
                                    mut_intrinsic,
                                    mut_vm_pool,
                                    mut_vp_pool,
                                    mut_vs_pool,
                                    mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                        };
                    };
                };
            };

        bsl::ut_scenario{"ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL non local vsid"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x0_u16};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{0x0_u16};
                constexpr auto ppid{0x1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, ppid));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{
            "ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL vp assigned to wrong vm"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x1_u16};
                constexpr auto vpid{0x0_u16};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = bsl::to_u64(vpid).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, vmid));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{
            "ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL vp assigned to wrong vm"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vmid{0x1_u16};
                constexpr auto vpid{0x1_u16};
                constexpr auto vsid{0x0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg3 = bsl::to_u64(vsid).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, vmid));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, vpid, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{
            "ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL vpid active on another core"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                tls_t mut_tls_remote{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto ppid{0x1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    mut_tls_remote.ppid = ppid.get();
                    mut_tls_remote.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_vp_pool.set_active(mut_tls_remote, {});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{
            "ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL vsid active on another core"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                tls_t mut_tls_remote{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto ppid{0x1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    mut_tls_remote.ppid = ppid.get();
                    mut_tls_remote.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vs_pool.set_active(mut_tls_remote, mut_intrinsic, {});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"TLB_FLUSH_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_TLB_FLUSH_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = HYPERVISOR_PAGE_SIZE.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"TLB_FLUSH_IDX_VAL invalid vsid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_TLB_FLUSH_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vsid{syscall::BF_INVALID_ID};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vsid).get();
                    mut_tls.ext_reg2 = HYPERVISOR_PAGE_SIZE.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"TLB_FLUSH_IDX_VAL invalid vsid #2"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_TLB_FLUSH_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto vsid{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vsid).get();
                    mut_tls.ext_reg2 = HYPERVISOR_PAGE_SIZE.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"TLB_FLUSH_IDX_VAL vsid never allocated"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_TLB_FLUSH_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = HYPERVISOR_PAGE_SIZE.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"TLB_FLUSH_IDX_VAL not locally assigned"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_TLB_FLUSH_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto ppid{0x1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = HYPERVISOR_PAGE_SIZE.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, ppid));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"TLB_FLUSH_IDX_VAL invalid gla #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_TLB_FLUSH_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"TLB_FLUSH_IDX_VAL invalid gla #2"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_TLB_FLUSH_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                constexpr auto gla{42_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.online_pps = bsl::to_u16(online_pps).get();
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = gla.get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vs_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
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
