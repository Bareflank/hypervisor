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

#include "../../../src/mk_main_t.hpp"

#include <basic_page_4k_t.hpp>
#include <basic_page_pool_node_t.hpp>
#include <basic_page_table_t.hpp>
#include <basic_root_page_table_t.hpp>
#include <bf_constants.hpp>
#include <debug_ring_t.hpp>
#include <ext_pool_t.hpp>
#include <ext_t.hpp>
#include <huge_pool_t.hpp>
#include <intrinsic_t.hpp>
#include <l3e_t.hpp>
#include <mk_args_t.hpp>
#include <page_pool_t.hpp>
#include <root_page_table_t.hpp>
#include <state_save_t.hpp>
#include <tls_t.hpp>
#include <vm_pool_t.hpp>
#include <vm_t.hpp>
#include <vmexit_log_t.hpp>
#include <vp_pool_t.hpp>
#include <vs_pool_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/span.hpp>
#include <bsl/ut.hpp>

namespace mk
{
    /// @brief stores the mk_state for this test
    loader::state_save_t g_mut_mk_state{};
    /// @brief stores the root_vp_state for this test
    loader::state_save_t g_mut_root_vp_state{};
    /// @brief stores the debug_ring for this test
    loader::debug_ring_t g_mut_debug_ring{};
    /// @brief stores the ext_elf_file for this test
    loader::ext_elf_file_t const g_ext_elf_file{};
    /// @brief stores the rpt for this test
    lib::basic_page_table_t<lib::l3e_t> g_mut_rpt{};
    /// @brief stores the page_pool for this test
    lib::basic_page_pool_node_t g_mut_page_pool{};
    /// @brief stores the huge_pool for this test
    lib::basic_page_4k_t g_mut_huge_pool{};

    /// <!-- description -->
    ///   @brief Creates and returns a tls_t for testing
    ///
    /// <!-- inputs/outputs -->
    ///   @return Creates and returns a tls_t for testing
    ///
    [[nodiscard]] constexpr auto
    create_tls() noexcept -> tls_t
    {
        constexpr auto online_pps{2_u16};

        tls_t mut_tls{};
        mut_tls.ppid = {};
        mut_tls.online_pps = online_pps.get();
        mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
        mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
        mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
        mut_tls.active_extid = syscall::BF_INVALID_ID.get();

        return mut_tls;
    }

    /// <!-- description -->
    ///   @brief Creates and returns a loader::mk_args_t for testing
    ///
    /// <!-- inputs/outputs -->
    ///   @return Creates and returns a loader::mk_args_t for testing
    ///
    [[nodiscard]] constexpr auto
    create_args() noexcept -> loader::mk_args_t
    {
        constexpr auto online_pps{2_u16};

        loader::mk_args_t mut_args{};
        mut_args.ppid = {};
        mut_args.online_pps = online_pps.get();
        mut_args.mk_state = &g_mut_mk_state;
        mut_args.root_vp_state = &g_mut_root_vp_state;
        mut_args.debug_ring = &g_mut_debug_ring;
        mut_args.ext_elf_files.front() = &g_ext_elf_file;
        mut_args.rpt = &g_mut_rpt;
        mut_args.rpt_phys = HYPERVISOR_PAGE_SIZE.get();
        mut_args.page_pool = bsl::span{&g_mut_page_pool, bsl::safe_umx::magic_1()};
        mut_args.huge_pool = bsl::span{&g_mut_huge_pool, bsl::safe_umx::magic_1()};

        return mut_args;
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
        bsl::ut_scenario{"process"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                mk_main_t mut_mk_main{};
                tls_t mut_tls{create_tls()};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_t mut_ext{};
                ext_pool_t mut_ext_pool{};
                root_page_table_t mut_system_rpt{};
                vmexit_log_t mut_log{};
                loader::mk_args_t mut_args{create_args()};
                root_page_table_t mut_rpt{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_fail = &mut_ext;
                    mut_tls.active_rpt = &mut_rpt;

                    mut_tls.ppid = bsl::safe_u16::magic_0().get();
                    mut_args.ppid = bsl::safe_u16::magic_0().get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_mk_main.process(
                            mut_tls,
                            mut_page_pool,
                            mut_huge_pool,
                            mut_intrinsic,
                            mut_vm_pool,
                            mut_vp_pool,
                            mut_vs_pool,
                            mut_ext_pool,
                            mut_system_rpt,
                            mut_log,
                            mut_args));
                    };

                    mut_tls.ppid = bsl::safe_u16::magic_1().get();
                    mut_args.ppid = bsl::safe_u16::magic_1().get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_mk_main.process(
                            mut_tls,
                            mut_page_pool,
                            mut_huge_pool,
                            mut_intrinsic,
                            mut_vm_pool,
                            mut_vp_pool,
                            mut_vs_pool,
                            mut_ext_pool,
                            mut_system_rpt,
                            mut_log,
                            mut_args));
                    };
                };
            };
        };

        bsl::ut_scenario{"process no vmexit handler"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                mk_main_t mut_mk_main{};
                tls_t mut_tls{create_tls()};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_t mut_ext{};
                ext_pool_t mut_ext_pool{};
                root_page_table_t mut_system_rpt{};
                vmexit_log_t mut_log{};
                loader::mk_args_t mut_args{create_args()};
                root_page_table_t mut_rpt{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_fail = &mut_ext;
                    mut_tls.active_rpt = &mut_rpt;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_mk_main.process(
                            mut_tls,
                            mut_page_pool,
                            mut_huge_pool,
                            mut_intrinsic,
                            mut_vm_pool,
                            mut_vp_pool,
                            mut_vs_pool,
                            mut_ext_pool,
                            mut_system_rpt,
                            mut_log,
                            mut_args));
                    };
                };
            };
        };

        bsl::ut_scenario{"process no fail handler"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                mk_main_t mut_mk_main{};
                tls_t mut_tls{create_tls()};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_t mut_ext{};
                ext_pool_t mut_ext_pool{};
                root_page_table_t mut_system_rpt{};
                vmexit_log_t mut_log{};
                loader::mk_args_t mut_args{create_args()};
                root_page_table_t mut_rpt{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.active_rpt = &mut_rpt;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_mk_main.process(
                            mut_tls,
                            mut_page_pool,
                            mut_huge_pool,
                            mut_intrinsic,
                            mut_vm_pool,
                            mut_vp_pool,
                            mut_vs_pool,
                            mut_ext_pool,
                            mut_system_rpt,
                            mut_log,
                            mut_args));
                    };
                };
            };
        };

        bsl::ut_scenario{"process rpt fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                mk_main_t mut_mk_main{};
                tls_t mut_tls{create_tls()};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_t mut_ext{};
                ext_pool_t mut_ext_pool{};
                root_page_table_t mut_system_rpt{};
                vmexit_log_t mut_log{};
                loader::mk_args_t mut_args{create_args()};
                root_page_table_t mut_rpt{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_fail = &mut_ext;
                    mut_tls.active_rpt = &mut_rpt;
                    mut_tls.test_ret = lib::UNIT_TEST_RPT_FAIL_INITIALIZE;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_mk_main.process(
                            mut_tls,
                            mut_page_pool,
                            mut_huge_pool,
                            mut_intrinsic,
                            mut_vm_pool,
                            mut_vp_pool,
                            mut_vs_pool,
                            mut_ext_pool,
                            mut_system_rpt,
                            mut_log,
                            mut_args));
                    };
                };
            };
        };

        bsl::ut_scenario{"process ext_pool fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                mk_main_t mut_mk_main{};
                tls_t mut_tls{create_tls()};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_t mut_ext{};
                ext_pool_t mut_ext_pool{};
                root_page_table_t mut_system_rpt{};
                vmexit_log_t mut_log{};
                loader::mk_args_t mut_args{create_args()};
                root_page_table_t mut_rpt{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_fail = &mut_ext;
                    mut_tls.active_rpt = &mut_rpt;
                    mut_tls.test_ret = UNIT_TEST_EXT_POOL_FAIL_INITIALIZE;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_mk_main.process(
                            mut_tls,
                            mut_page_pool,
                            mut_huge_pool,
                            mut_intrinsic,
                            mut_vm_pool,
                            mut_vp_pool,
                            mut_vs_pool,
                            mut_ext_pool,
                            mut_system_rpt,
                            mut_log,
                            mut_args));
                    };
                };
            };
        };

        bsl::ut_scenario{"process vm_pool fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                mk_main_t mut_mk_main{};
                tls_t mut_tls{create_tls()};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_t mut_ext{};
                ext_pool_t mut_ext_pool{};
                root_page_table_t mut_system_rpt{};
                vmexit_log_t mut_log{};
                loader::mk_args_t mut_args{create_args()};
                root_page_table_t mut_rpt{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_fail = &mut_ext;
                    mut_tls.active_rpt = &mut_rpt;
                    mut_tls.test_ret = UNIT_TEST_VM_FAIL_ALLOCATE;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_mk_main.process(
                            mut_tls,
                            mut_page_pool,
                            mut_huge_pool,
                            mut_intrinsic,
                            mut_vm_pool,
                            mut_vp_pool,
                            mut_vs_pool,
                            mut_ext_pool,
                            mut_system_rpt,
                            mut_log,
                            mut_args));
                    };
                };
            };
        };

        bsl::ut_scenario{"process start fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                mk_main_t mut_mk_main{};
                tls_t mut_tls{create_tls()};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_t mut_ext{};
                ext_pool_t mut_ext_pool{};
                root_page_table_t mut_system_rpt{};
                vmexit_log_t mut_log{};
                loader::mk_args_t mut_args{create_args()};
                root_page_table_t mut_rpt{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_fail = &mut_ext;
                    mut_tls.active_rpt = &mut_rpt;
                    mut_tls.test_ret = UNIT_TEST_EXT_POOL_FAIL_START;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_mk_main.process(
                            mut_tls,
                            mut_page_pool,
                            mut_huge_pool,
                            mut_intrinsic,
                            mut_vm_pool,
                            mut_vp_pool,
                            mut_vs_pool,
                            mut_ext_pool,
                            mut_system_rpt,
                            mut_log,
                            mut_args));
                    };
                };
            };
        };

        bsl::ut_scenario{"process bootstrap fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                mk_main_t mut_mk_main{};
                tls_t mut_tls{create_tls()};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                intrinsic_t mut_intrinsic{};
                vm_pool_t mut_vm_pool{};
                vp_pool_t mut_vp_pool{};
                vs_pool_t mut_vs_pool{};
                ext_t mut_ext{};
                ext_pool_t mut_ext_pool{};
                root_page_table_t mut_system_rpt{};
                vmexit_log_t mut_log{};
                loader::mk_args_t mut_args{create_args()};
                root_page_table_t mut_rpt{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_vmexit = &mut_ext;
                    mut_tls.ext_fail = &mut_ext;
                    mut_tls.active_rpt = &mut_rpt;
                    mut_tls.test_ret = UNIT_TEST_EXT_POOL_FAIL_BOOTSTRAP;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_mk_main.process(
                            mut_tls,
                            mut_page_pool,
                            mut_huge_pool,
                            mut_intrinsic,
                            mut_vm_pool,
                            mut_vp_pool,
                            mut_vs_pool,
                            mut_ext_pool,
                            mut_system_rpt,
                            mut_log,
                            mut_args));
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
