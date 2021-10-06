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

#include "../../../mocks/bf_syscall_impl.hpp"

#include <bsl/ut.hpp>

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

    bsl::ut_scenario{"verify noexcept"} = []() noexcept {
        bsl::ut_then{} = []() noexcept {
            static_assert(noexcept(syscall::dummy_bootstrap_entry({})));
            static_assert(noexcept(syscall::dummy_vmexit_entry({}, {})));
            static_assert(noexcept(syscall::dummy_fail_entry({}, {})));
            static_assert(noexcept(syscall::bf_tls_set_rax_impl({})));
            static_assert(noexcept(syscall::bf_tls_rax_impl()));
            static_assert(noexcept(syscall::bf_tls_set_rbx_impl({})));
            static_assert(noexcept(syscall::bf_tls_rbx_impl()));
            static_assert(noexcept(syscall::bf_tls_set_rcx_impl({})));
            static_assert(noexcept(syscall::bf_tls_rcx_impl()));
            static_assert(noexcept(syscall::bf_tls_set_rdx_impl({})));
            static_assert(noexcept(syscall::bf_tls_rdx_impl()));
            static_assert(noexcept(syscall::bf_tls_set_rbp_impl({})));
            static_assert(noexcept(syscall::bf_tls_rbp_impl()));
            static_assert(noexcept(syscall::bf_tls_set_rsi_impl({})));
            static_assert(noexcept(syscall::bf_tls_rsi_impl()));
            static_assert(noexcept(syscall::bf_tls_set_rdi_impl({})));
            static_assert(noexcept(syscall::bf_tls_rdi_impl()));
            static_assert(noexcept(syscall::bf_tls_set_r8_impl({})));
            static_assert(noexcept(syscall::bf_tls_r8_impl()));
            static_assert(noexcept(syscall::bf_tls_set_r9_impl({})));
            static_assert(noexcept(syscall::bf_tls_r9_impl()));
            static_assert(noexcept(syscall::bf_tls_set_r10_impl({})));
            static_assert(noexcept(syscall::bf_tls_r10_impl()));
            static_assert(noexcept(syscall::bf_tls_set_r11_impl({})));
            static_assert(noexcept(syscall::bf_tls_r11_impl()));
            static_assert(noexcept(syscall::bf_tls_set_r12_impl({})));
            static_assert(noexcept(syscall::bf_tls_r12_impl()));
            static_assert(noexcept(syscall::bf_tls_set_r13_impl({})));
            static_assert(noexcept(syscall::bf_tls_r13_impl()));
            static_assert(noexcept(syscall::bf_tls_set_r14_impl({})));
            static_assert(noexcept(syscall::bf_tls_r14_impl()));
            static_assert(noexcept(syscall::bf_tls_set_r15_impl({})));
            static_assert(noexcept(syscall::bf_tls_r15_impl()));
            static_assert(noexcept(syscall::bf_tls_extid_impl()));
            static_assert(noexcept(syscall::bf_tls_vmid_impl()));
            static_assert(noexcept(syscall::bf_tls_vpid_impl()));
            static_assert(noexcept(syscall::bf_tls_vsid_impl()));
            static_assert(noexcept(syscall::bf_tls_ppid_impl()));
            static_assert(noexcept(syscall::bf_tls_online_pps_impl()));
            static_assert(noexcept(syscall::bf_control_op_exit_impl()));
            static_assert(noexcept(syscall::bf_control_op_wait_impl()));
            static_assert(noexcept(syscall::bf_control_op_again_impl()));
            static_assert(noexcept(syscall::bf_handle_op_open_handle_impl({}, {})));
            static_assert(noexcept(syscall::bf_handle_op_close_handle_impl({})));
            static_assert(noexcept(syscall::bf_debug_op_out_impl({}, {})));
            static_assert(noexcept(syscall::bf_debug_op_dump_vm_impl({})));
            static_assert(noexcept(syscall::bf_debug_op_dump_vp_impl({})));
            static_assert(noexcept(syscall::bf_debug_op_dump_vs_impl({})));
            static_assert(noexcept(syscall::bf_debug_op_dump_vmexit_log_impl({})));
            static_assert(noexcept(syscall::bf_debug_op_dump_vmexit_log_impl({})));
            static_assert(noexcept(syscall::bf_debug_op_write_c_impl({})));
            static_assert(noexcept(syscall::bf_debug_op_write_str_impl({}, {})));
            static_assert(noexcept(syscall::bf_debug_op_dump_ext_impl({})));
            static_assert(noexcept(syscall::bf_debug_op_dump_page_pool_impl()));
            static_assert(noexcept(syscall::bf_debug_op_dump_huge_pool_impl()));
            static_assert(noexcept(syscall::bf_callback_op_register_bootstrap_impl({}, {})));
            static_assert(noexcept(syscall::bf_callback_op_register_vmexit_impl({}, {})));
            static_assert(noexcept(syscall::bf_callback_op_register_fail_impl({}, {})));
            static_assert(noexcept(syscall::bf_vm_op_create_vm_impl({}, {})));
            static_assert(noexcept(syscall::bf_vm_op_destroy_vm_impl({}, {})));
            static_assert(noexcept(syscall::bf_vm_op_map_direct_impl({}, {}, {}, {})));
            static_assert(noexcept(syscall::bf_vm_op_unmap_direct_impl({}, {}, {})));
            static_assert(noexcept(syscall::bf_vm_op_unmap_direct_broadcast_impl({}, {}, {})));
            static_assert(noexcept(syscall::bf_vm_op_tlb_flush_impl({}, {})));
            static_assert(noexcept(syscall::bf_vp_op_create_vp_impl({}, {}, {})));
            static_assert(noexcept(syscall::bf_vp_op_destroy_vp_impl({}, {})));
            static_assert(noexcept(syscall::bf_vs_op_create_vs_impl({}, {}, {}, {})));
            static_assert(noexcept(syscall::bf_vs_op_destroy_vs_impl({}, {})));
            static_assert(noexcept(syscall::bf_vs_op_init_as_root_impl({}, {})));
            static_assert(noexcept(syscall::bf_vs_op_read_impl({}, {}, {}, {})));
            static_assert(noexcept(syscall::bf_vs_op_write_impl({}, {}, {}, {})));
            static_assert(noexcept(syscall::bf_vs_op_run_impl({}, {}, {}, {})));
            static_assert(noexcept(syscall::bf_vs_op_run_current_impl({})));
            static_assert(noexcept(syscall::bf_vs_op_advance_ip_and_run_impl({}, {}, {}, {})));
            static_assert(noexcept(syscall::bf_vs_op_advance_ip_and_run_current_impl({})));
            static_assert(noexcept(syscall::bf_vs_op_promote_impl({}, {})));
            static_assert(noexcept(syscall::bf_vs_op_clear_impl({}, {})));
            static_assert(noexcept(syscall::bf_vs_op_migrate_impl({}, {}, {})));
            static_assert(noexcept(syscall::bf_vs_op_set_active_impl({}, {}, {}, {})));
            static_assert(
                noexcept(syscall::bf_vs_op_advance_ip_and_set_active_impl({}, {}, {}, {})));
            static_assert(noexcept(syscall::bf_vs_op_tlb_flush_impl({}, {}, {})));
            static_assert(noexcept(syscall::bf_intrinsic_op_rdmsr_impl({}, {}, {})));
            static_assert(noexcept(syscall::bf_intrinsic_op_wrmsr_impl({}, {}, {})));
            static_assert(noexcept(syscall::bf_mem_op_alloc_page_impl({}, {}, {})));
            static_assert(noexcept(syscall::bf_mem_op_alloc_huge_impl({}, {}, {}, {})));
        };
    };

    return bsl::ut_success();
}
