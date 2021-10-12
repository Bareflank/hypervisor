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

#include "../../../mocks/bf_syscall_t.hpp"

#include <basic_page_4k_t.hpp>

#include <bsl/discard.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/ut.hpp>

namespace syscall
{
    /// @brief verify constinit it supported
    constinit bf_syscall_t const g_verify_constinit{};
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
    using page_t = lib::basic_page_4k_t;

    bsl::ut_scenario{"verify supports constinit"} = []() noexcept {
        bsl::discard(syscall::g_verify_constinit);
    };

    bsl::ut_scenario{"verify noexcept"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            syscall::bf_syscall_t mut_sys{};
            syscall::bf_syscall_t const sys{};
            bsl::safe_u64 mut_phys{};
            bsl::ut_then{} = []() noexcept {
                static_assert(noexcept(syscall::bf_syscall_t{}));

                static_assert(noexcept(mut_sys.initialize({}, {}, {}, {})));
                static_assert(noexcept(mut_sys.set_initialize({})));
                static_assert(noexcept(mut_sys.release()));
                static_assert(noexcept(mut_sys.bf_tls_rax()));
                static_assert(noexcept(mut_sys.bf_tls_set_rax({})));
                static_assert(noexcept(mut_sys.bf_tls_rbx()));
                static_assert(noexcept(mut_sys.bf_tls_set_rbx({})));
                static_assert(noexcept(mut_sys.bf_tls_rcx()));
                static_assert(noexcept(mut_sys.bf_tls_set_rcx({})));
                static_assert(noexcept(mut_sys.bf_tls_rdx()));
                static_assert(noexcept(mut_sys.bf_tls_set_rdx({})));
                static_assert(noexcept(mut_sys.bf_tls_rbp()));
                static_assert(noexcept(mut_sys.bf_tls_set_rbp({})));
                static_assert(noexcept(mut_sys.bf_tls_rsi()));
                static_assert(noexcept(mut_sys.bf_tls_set_rsi({})));
                static_assert(noexcept(mut_sys.bf_tls_rdi()));
                static_assert(noexcept(mut_sys.bf_tls_set_rdi({})));
                static_assert(noexcept(mut_sys.bf_tls_r8()));
                static_assert(noexcept(mut_sys.bf_tls_set_r8({})));
                static_assert(noexcept(mut_sys.bf_tls_r9()));
                static_assert(noexcept(mut_sys.bf_tls_set_r9({})));
                static_assert(noexcept(mut_sys.bf_tls_r10()));
                static_assert(noexcept(mut_sys.bf_tls_set_r10({})));
                static_assert(noexcept(mut_sys.bf_tls_r11()));
                static_assert(noexcept(mut_sys.bf_tls_set_r11({})));
                static_assert(noexcept(mut_sys.bf_tls_r12()));
                static_assert(noexcept(mut_sys.bf_tls_set_r12({})));
                static_assert(noexcept(mut_sys.bf_tls_r13()));
                static_assert(noexcept(mut_sys.bf_tls_set_r13({})));
                static_assert(noexcept(mut_sys.bf_tls_r14()));
                static_assert(noexcept(mut_sys.bf_tls_set_r14({})));
                static_assert(noexcept(mut_sys.bf_tls_r15()));
                static_assert(noexcept(mut_sys.bf_tls_set_r15({})));
                static_assert(noexcept(mut_sys.bf_tls_extid()));
                static_assert(noexcept(mut_sys.bf_tls_set_extid({})));
                static_assert(noexcept(mut_sys.bf_tls_vmid()));
                static_assert(noexcept(mut_sys.bf_tls_set_vmid({})));
                static_assert(noexcept(mut_sys.bf_tls_vpid()));
                static_assert(noexcept(mut_sys.bf_tls_set_vpid({})));
                static_assert(noexcept(mut_sys.bf_tls_vsid()));
                static_assert(noexcept(mut_sys.bf_tls_set_vsid({})));
                static_assert(noexcept(mut_sys.bf_tls_ppid()));
                static_assert(noexcept(mut_sys.bf_tls_set_ppid({})));
                static_assert(noexcept(mut_sys.bf_tls_online_pps()));
                static_assert(noexcept(mut_sys.bf_tls_set_online_pps({})));
                static_assert(noexcept(mut_sys.bf_vm_op_create_vm()));
                static_assert(noexcept(mut_sys.set_bf_vm_op_create_vm({})));
                static_assert(noexcept(mut_sys.bf_vm_op_destroy_vm({})));
                static_assert(noexcept(mut_sys.set_bf_vm_op_destroy_vm({}, {})));
                static_assert(noexcept(mut_sys.bf_vm_op_map_direct<page_t>({}, {})));
                static_assert(noexcept(mut_sys.set_bf_vm_op_map_direct({}, {})));
                static_assert(noexcept(mut_sys.bf_vm_op_unmap_direct<page_t>({}, {})));
                static_assert(noexcept(mut_sys.set_bf_vm_op_unmap_direct({}, {})));
                static_assert(noexcept(mut_sys.bf_vm_op_unmap_direct_broadcast<page_t>({}, {})));
                static_assert(noexcept(mut_sys.set_bf_vm_op_unmap_direct_broadcast({}, {})));
                static_assert(noexcept(mut_sys.bf_vm_op_tlb_flush({})));
                static_assert(noexcept(mut_sys.set_bf_vm_op_tlb_flush({}, {})));
                static_assert(noexcept(mut_sys.bf_vp_op_create_vp({})));
                static_assert(noexcept(mut_sys.set_bf_vp_op_create_vp({}, {})));
                static_assert(noexcept(mut_sys.bf_vp_op_destroy_vp({})));
                static_assert(noexcept(mut_sys.set_bf_vp_op_destroy_vp({}, {})));
                static_assert(noexcept(mut_sys.bf_vs_op_create_vs({}, {})));
                static_assert(noexcept(mut_sys.set_bf_vs_op_create_vs({}, {}, {})));
                static_assert(noexcept(mut_sys.bf_vs_op_destroy_vs({})));
                static_assert(noexcept(mut_sys.set_bf_vs_op_destroy_vs({}, {})));
                static_assert(noexcept(mut_sys.bf_vs_op_init_as_root({})));
                static_assert(noexcept(mut_sys.set_bf_vs_op_init_as_root({}, {})));
                static_assert(noexcept(mut_sys.bf_vs_op_read({}, {})));
                static_assert(noexcept(mut_sys.set_bf_vs_op_read({}, {}, {})));
                static_assert(noexcept(mut_sys.bf_vs_op_write({}, {}, {})));
                static_assert(noexcept(mut_sys.set_bf_vs_op_write({}, {}, {}, {})));
                static_assert(noexcept(mut_sys.bf_vs_op_run({}, {}, {})));
                static_assert(noexcept(mut_sys.set_bf_vs_op_run({}, {}, {}, {})));
                static_assert(noexcept(mut_sys.bf_vs_op_run_current()));
                static_assert(noexcept(mut_sys.set_bf_vs_op_run_current({})));
                static_assert(noexcept(mut_sys.bf_vs_op_advance_ip_and_run({}, {}, {})));
                static_assert(noexcept(mut_sys.set_bf_vs_op_advance_ip_and_run({}, {}, {}, {})));
                static_assert(noexcept(mut_sys.bf_vs_op_advance_ip_and_run_current()));
                static_assert(noexcept(mut_sys.set_bf_vs_op_advance_ip_and_run_current({})));
                static_assert(noexcept(mut_sys.bf_vs_op_promote({})));
                static_assert(noexcept(mut_sys.set_bf_vs_op_promote({}, {})));
                static_assert(noexcept(mut_sys.bf_vs_op_clear({})));
                static_assert(noexcept(mut_sys.set_bf_vs_op_clear({}, {})));
                static_assert(noexcept(mut_sys.bf_vs_op_migrate({}, {})));
                static_assert(noexcept(mut_sys.set_bf_vs_op_migrate({}, {}, {})));
                static_assert(noexcept(mut_sys.bf_vs_op_set_active({}, {}, {})));
                static_assert(noexcept(mut_sys.set_bf_vs_op_set_active({}, {}, {}, {})));
                static_assert(noexcept(mut_sys.bf_vs_op_advance_ip_and_set_active({}, {}, {})));
                static_assert(
                    noexcept(mut_sys.set_bf_vs_op_advance_ip_and_set_active({}, {}, {}, {})));
                static_assert(noexcept(mut_sys.bf_vs_op_tlb_flush({}, {})));
                static_assert(noexcept(mut_sys.set_bf_vs_op_tlb_flush({}, {}, {})));
                static_assert(noexcept(mut_sys.bf_intrinsic_op_rdmsr({})));
                static_assert(noexcept(mut_sys.set_bf_intrinsic_op_rdmsr({}, {})));
                static_assert(noexcept(mut_sys.bf_intrinsic_op_wrmsr({}, {})));
                static_assert(noexcept(mut_sys.set_bf_intrinsic_op_wrmsr({}, {}, {})));
                static_assert(noexcept(mut_sys.bf_mem_op_alloc_page<page_t>(mut_phys)));
                static_assert(noexcept(mut_sys.bf_mem_op_alloc_page<page_t>()));
                static_assert(noexcept(mut_sys.set_bf_mem_op_alloc_page({})));
                static_assert(noexcept(mut_sys.bf_mem_op_alloc_huge<page_t>({}, mut_phys)));
                static_assert(noexcept(mut_sys.bf_mem_op_alloc_huge<page_t>({})));
                static_assert(noexcept(mut_sys.set_bf_mem_op_alloc_huge({})));

                static_assert(noexcept(sys.bf_tls_rax()));
                static_assert(noexcept(sys.bf_tls_rbx()));
                static_assert(noexcept(sys.bf_tls_rcx()));
                static_assert(noexcept(sys.bf_tls_rdx()));
                static_assert(noexcept(sys.bf_tls_rbp()));
                static_assert(noexcept(sys.bf_tls_rsi()));
                static_assert(noexcept(sys.bf_tls_rdi()));
                static_assert(noexcept(sys.bf_tls_r8()));
                static_assert(noexcept(sys.bf_tls_r9()));
                static_assert(noexcept(sys.bf_tls_r10()));
                static_assert(noexcept(sys.bf_tls_r11()));
                static_assert(noexcept(sys.bf_tls_r12()));
                static_assert(noexcept(sys.bf_tls_r13()));
                static_assert(noexcept(sys.bf_tls_r14()));
                static_assert(noexcept(sys.bf_tls_r15()));
                static_assert(noexcept(sys.bf_tls_extid()));
                static_assert(noexcept(sys.bf_tls_vmid()));
                static_assert(noexcept(sys.bf_tls_vpid()));
                static_assert(noexcept(sys.bf_tls_vsid()));
                static_assert(noexcept(sys.bf_tls_ppid()));
                static_assert(noexcept(sys.bf_tls_online_pps()));
                static_assert(noexcept(sys.bf_vs_op_read({}, {})));
                static_assert(noexcept(sys.bf_intrinsic_op_rdmsr({})));
            };
        };
    };

    return bsl::ut_success();
}
