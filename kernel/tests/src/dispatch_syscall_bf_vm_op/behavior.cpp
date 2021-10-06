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

#include "../../../src/dispatch_syscall_bf_vm_op.hpp"

#include <bf_constants.hpp>
#include <ext_pool_t.hpp>
#include <ext_t.hpp>
#include <intrinsic_t.hpp>
#include <page_pool_t.hpp>
#include <tls_t.hpp>
#include <vm_pool_t.hpp>
#include <vp_pool_t.hpp>
#include <vs_pool_t.hpp>

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
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
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
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{0xFFFFFFFFFFFFFFFF_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
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
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{0xFFFFFFFFFFFFFFFF_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext = &mut_ext;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"CREATE_VM_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_CREATE_VM_IDX_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"CREATE_VM_IDX_VAL too many vms"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_CREATE_VM_IDX_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vm_pool.initialize();
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    auto const hndl{bsl::to_u64(mut_ext.open_handle())};

                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = hndl.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) == syscall::BF_STATUS_SUCCESS);
                    };

                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = hndl.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) == syscall::BF_STATUS_SUCCESS);
                    };

                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = hndl.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"DESTROY_VM_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_DESTROY_VM_IDX_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"DESTROY_VM_IDX_VAL invalid vmid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_DESTROY_VM_IDX_VAL};
                constexpr auto vmid{syscall::BF_INVALID_ID};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_vm_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"DESTROY_VM_IDX_VAL invalid vmid #2"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_DESTROY_VM_IDX_VAL};
                constexpr auto vmid{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_vm_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"DESTROY_VM_IDX_VAL not allocated"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_DESTROY_VM_IDX_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"DESTROY_VM_IDX_VAL still active"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_DESTROY_VM_IDX_VAL};
                constexpr auto online_pps{0x2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.online_pps = online_pps.get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_vm_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    mut_vm_pool.set_active(mut_tls, {});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"DESTROY_VM_IDX_VAL still active"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_DESTROY_VM_IDX_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    mut_vp_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_required_step(mut_vp_pool.allocate(mut_tls, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
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

        bsl::ut_scenario{"MAP_DIRECT_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_MAP_DIRECT_IDX_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = HYPERVISOR_PAGE_SIZE.get();
                    mut_vm_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"MAP_DIRECT_IDX_VAL invalid vmid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_MAP_DIRECT_IDX_VAL};
                constexpr auto vmid{syscall::BF_INVALID_ID};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = HYPERVISOR_PAGE_SIZE.get();
                    mut_vm_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"MAP_DIRECT_IDX_VAL invalid vmid #2"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_MAP_DIRECT_IDX_VAL};
                constexpr auto vmid{42_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = HYPERVISOR_PAGE_SIZE.get();
                    mut_vm_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"MAP_DIRECT_IDX_VAL never allocated"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_MAP_DIRECT_IDX_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = HYPERVISOR_PAGE_SIZE.get();
                    mut_vm_pool.initialize();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"MAP_DIRECT_IDX_VAL invalid phys #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_MAP_DIRECT_IDX_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_vm_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"MAP_DIRECT_IDX_VAL invalid phys #2"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_MAP_DIRECT_IDX_VAL};
                constexpr auto phys{HYPERVISOR_EXT_DIRECT_MAP_SIZE};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = phys.get();
                    mut_vm_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"MAP_DIRECT_IDX_VAL invalid phys #3"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_MAP_DIRECT_IDX_VAL};
                constexpr auto phys{42_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = phys.get();
                    mut_vm_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"MAP_DIRECT_IDX_VAL map_page_direct fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_MAP_DIRECT_IDX_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = HYPERVISOR_PAGE_SIZE.get();
                    mut_vm_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    mut_tls.test_virt = bsl::safe_u64::failure();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"UNMAP_DIRECT_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_UNMAP_DIRECT_IDX_VAL};
                constexpr auto virt{(HYPERVISOR_EXT_DIRECT_MAP_ADDR + 0x1000_u64).checked()};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = virt.get();
                    mut_vm_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"UNMAP_DIRECT_IDX_VAL invalid vmid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_UNMAP_DIRECT_IDX_VAL};
                constexpr auto vmid{syscall::BF_INVALID_ID};
                constexpr auto virt{(HYPERVISOR_EXT_DIRECT_MAP_ADDR + 0x1000_u64).checked()};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = virt.get();
                    mut_vm_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"UNMAP_DIRECT_IDX_VAL invalid vmid #2"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_UNMAP_DIRECT_IDX_VAL};
                constexpr auto vmid{42_u64};
                constexpr auto virt{(HYPERVISOR_EXT_DIRECT_MAP_ADDR + 0x1000_u64).checked()};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = virt.get();
                    mut_vm_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"UNMAP_DIRECT_IDX_VAL never allocated"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_UNMAP_DIRECT_IDX_VAL};
                constexpr auto virt{(HYPERVISOR_EXT_DIRECT_MAP_ADDR + 0x1000_u64).checked()};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = virt.get();
                    mut_vm_pool.initialize();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"UNMAP_DIRECT_IDX_VAL invalid virt #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_UNMAP_DIRECT_IDX_VAL};
                constexpr auto virt{0x0_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = virt.get();
                    mut_vm_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"UNMAP_DIRECT_IDX_VAL invalid virt #2"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_UNMAP_DIRECT_IDX_VAL};
                constexpr auto virt{HYPERVISOR_EXT_DIRECT_MAP_ADDR};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = virt.get();
                    mut_vm_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"UNMAP_DIRECT_IDX_VAL invalid virt #3"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_UNMAP_DIRECT_IDX_VAL};
                constexpr auto virt{bsl::safe_u64::max_value()};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = virt.get();
                    mut_vm_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"UNMAP_DIRECT_IDX_VAL invalid virt #4"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_UNMAP_DIRECT_IDX_VAL};
                constexpr auto virt{(HYPERVISOR_EXT_DIRECT_MAP_ADDR + 0x1042_u64).checked()};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = virt.get();
                    mut_vm_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"UNMAP_DIRECT_IDX_VAL fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_UNMAP_DIRECT_IDX_VAL};
                constexpr auto virt{(HYPERVISOR_EXT_DIRECT_MAP_ADDR + 0x1000_u64).checked()};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = virt.get();
                    mut_vm_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    mut_tls.test_ret = bsl::errc_failure;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"UNMAP_DIRECT_BROADCAST_IDX_VAL fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_UNMAP_DIRECT_BROADCAST_IDX_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
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
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_TLB_FLUSH_IDX_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = HYPERVISOR_PAGE_SIZE.get();
                    mut_vm_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"TLB_FLUSH_IDX_VAL invalid vmid #1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_TLB_FLUSH_IDX_VAL};
                constexpr auto vmid{syscall::BF_INVALID_ID};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = HYPERVISOR_PAGE_SIZE.get();
                    mut_vm_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"TLB_FLUSH_IDX_VAL invalid vmid #2"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_TLB_FLUSH_IDX_VAL};
                constexpr auto vmid{42_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = bsl::to_u64(vmid).get();
                    mut_tls.ext_reg2 = HYPERVISOR_PAGE_SIZE.get();
                    mut_vm_pool.initialize();
                    bsl::ut_required_step(
                        mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
                                mut_vs_pool,
                                mut_ext_pool) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"TLB_FLUSH_IDX_VAL never allocated"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t const vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_TLB_FLUSH_IDX_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg2 = HYPERVISOR_PAGE_SIZE.get();
                    mut_vm_pool.initialize();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_vm_op(
                                mut_tls,
                                mut_page_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                vp_pool,
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
