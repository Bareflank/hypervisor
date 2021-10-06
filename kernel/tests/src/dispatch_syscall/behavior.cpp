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

#include "../../../src/dispatch_syscall.hpp"

#include <bf_constants.hpp>
#include <dispatch_syscall_bf_callback_op.hpp>
#include <dispatch_syscall_bf_control_op.hpp>
#include <dispatch_syscall_bf_debug_op.hpp>
#include <dispatch_syscall_bf_handle_op.hpp>
#include <dispatch_syscall_bf_intrinsic_op.hpp>
#include <dispatch_syscall_bf_mem_op.hpp>
#include <dispatch_syscall_bf_vm_op.hpp>
#include <dispatch_syscall_bf_vp_op.hpp>
#include <dispatch_syscall_bf_vs_op.hpp>
#include <ext_pool_t.hpp>
#include <ext_t.hpp>
#include <huge_pool_t.hpp>
#include <intrinsic_t.hpp>
#include <page_pool_t.hpp>
#include <tls_t.hpp>
#include <vm_pool_t.hpp>
#include <vmexit_log_t.hpp>
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
        bsl::ut_scenario{"unknown syscall"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                vmexit_log_t mut_log{};
                ext_t mut_ext{};
                constexpr auto syscall{0xFFFFFFFFFFFFFFFF_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall(
                                mut_tls,
                                mut_page_pool,
                                mut_huge_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool,
                                mut_log) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"BF_CONTROL_OP_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                vmexit_log_t mut_log{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_CONTROL_OP_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall(
                                mut_tls,
                                mut_page_pool,
                                mut_huge_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool,
                                mut_log) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"BF_CONTROL_OP_VAL fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                vmexit_log_t mut_log{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_CONTROL_OP_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.test_ret = SYSCALL_BF_CONTROL_OP_FAILS;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall(
                                mut_tls,
                                mut_page_pool,
                                mut_huge_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool,
                                mut_log) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"BF_HANDLE_OP_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                vmexit_log_t mut_log{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_HANDLE_OP_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall(
                                mut_tls,
                                mut_page_pool,
                                mut_huge_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool,
                                mut_log) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"BF_HANDLE_OP_VAL fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                vmexit_log_t mut_log{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_HANDLE_OP_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.test_ret = SYSCALL_BF_HANDLE_OP_FAILS;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall(
                                mut_tls,
                                mut_page_pool,
                                mut_huge_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool,
                                mut_log) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"BF_DEBUG_OP_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                vmexit_log_t mut_log{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_DEBUG_OP_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall(
                                mut_tls,
                                mut_page_pool,
                                mut_huge_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool,
                                mut_log) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"BF_DEBUG_OP_VAL fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                vmexit_log_t mut_log{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_DEBUG_OP_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.test_ret = SYSCALL_BF_DEBUG_OP_FAILS;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall(
                                mut_tls,
                                mut_page_pool,
                                mut_huge_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool,
                                mut_log) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"BF_CALLBACK_OP_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                vmexit_log_t mut_log{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_CALLBACK_OP_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall(
                                mut_tls,
                                mut_page_pool,
                                mut_huge_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool,
                                mut_log) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"BF_CALLBACK_OP_VAL fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                vmexit_log_t mut_log{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_CALLBACK_OP_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.test_ret = SYSCALL_BF_CALLBACK_OP_FAILS;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall(
                                mut_tls,
                                mut_page_pool,
                                mut_huge_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool,
                                mut_log) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"BF_VM_OP_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                vmexit_log_t mut_log{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall(
                                mut_tls,
                                mut_page_pool,
                                mut_huge_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool,
                                mut_log) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"BF_VM_OP_VAL fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                vmexit_log_t mut_log{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VM_OP_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.test_ret = SYSCALL_BF_VM_OP_FAILS;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall(
                                mut_tls,
                                mut_page_pool,
                                mut_huge_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool,
                                mut_log) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"BF_VP_OP_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                vmexit_log_t mut_log{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VP_OP_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall(
                                mut_tls,
                                mut_page_pool,
                                mut_huge_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool,
                                mut_log) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"BF_VP_OP_VAL fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                vmexit_log_t mut_log{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VP_OP_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.test_ret = SYSCALL_BF_VP_OP_FAILS;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall(
                                mut_tls,
                                mut_page_pool,
                                mut_huge_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool,
                                mut_log) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"BF_VS_OP_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                vmexit_log_t mut_log{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall(
                                mut_tls,
                                mut_page_pool,
                                mut_huge_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool,
                                mut_log) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"BF_VS_OP_VAL fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                vmexit_log_t mut_log{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_VS_OP_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.test_ret = SYSCALL_BF_VS_OP_FAILS;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall(
                                mut_tls,
                                mut_page_pool,
                                mut_huge_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool,
                                mut_log) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"BF_INTRINSIC_OP_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                vmexit_log_t mut_log{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_INTRINSIC_OP_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall(
                                mut_tls,
                                mut_page_pool,
                                mut_huge_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool,
                                mut_log) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"BF_INTRINSIC_OP_VAL fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                vmexit_log_t mut_log{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_INTRINSIC_OP_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.test_ret = SYSCALL_BF_INTRINSIC_OP_FAILS;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall(
                                mut_tls,
                                mut_page_pool,
                                mut_huge_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool,
                                mut_log) != syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"BF_MEM_OP_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                vmexit_log_t mut_log{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_MEM_OP_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall(
                                mut_tls,
                                mut_page_pool,
                                mut_huge_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool,
                                mut_log) == syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"BF_MEM_OP_VAL fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_pool_t mut_ext_pool{};
                vmexit_log_t mut_log{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_MEM_OP_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.test_ret = SYSCALL_BF_MEM_OP_FAILS;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mk::dispatch_syscall(
                                mut_tls,
                                mut_page_pool,
                                mut_huge_pool,
                                mut_intrinsic,
                                mut_vm_pool,
                                mut_vp_pool,
                                mut_vs_pool,
                                mut_ext_pool,
                                mut_log) != syscall::BF_STATUS_SUCCESS);
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
