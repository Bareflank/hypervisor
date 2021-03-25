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

#include "../../../../src/cpp/bf_syscall_t.hpp"

#include <bsl/discard.hpp>
#include <bsl/ut.hpp>

namespace syscall
{
    constinit bf_syscall_t const g_verify_constinit{};

    // NOLINTNEXTLINE(bsl-user-defined-type-names-match-header-name)
    class fixture_t final
    {
        bf_syscall_t m_sys{};

    public:
        [[nodiscard]] constexpr auto
        test_member_const() const noexcept -> bool
        {
            bsl::discard(m_sys.bf_tls_rax());
            bsl::discard(m_sys.bf_tls_rbx());
            bsl::discard(m_sys.bf_tls_rcx());
            bsl::discard(m_sys.bf_tls_rdx());
            bsl::discard(m_sys.bf_tls_rbp());
            bsl::discard(m_sys.bf_tls_rsi());
            bsl::discard(m_sys.bf_tls_rdi());
            bsl::discard(m_sys.bf_tls_r8());
            bsl::discard(m_sys.bf_tls_r9());
            bsl::discard(m_sys.bf_tls_r10());
            bsl::discard(m_sys.bf_tls_r11());
            bsl::discard(m_sys.bf_tls_r12());
            bsl::discard(m_sys.bf_tls_r13());
            bsl::discard(m_sys.bf_tls_r14());
            bsl::discard(m_sys.bf_tls_r15());
            bsl::discard(m_sys.bf_tls_extid());
            bsl::discard(m_sys.bf_tls_vmid());
            bsl::discard(m_sys.bf_tls_vpid());
            bsl::discard(m_sys.bf_tls_vpsid());
            bsl::discard(m_sys.bf_tls_ppid());
            bsl::discard(m_sys.bf_tls_online_pps());
            bsl::discard(m_sys.bf_vps_op_read8({}, {}));
            bsl::discard(m_sys.bf_vps_op_read16({}, {}));
            bsl::discard(m_sys.bf_vps_op_read32({}, {}));
            bsl::discard(m_sys.bf_vps_op_read64({}, {}));
            bsl::discard(m_sys.bf_vps_op_read_reg({}, {}));
            bsl::discard(m_sys.bf_intrinsic_op_rdmsr({}));
            bsl::discard(m_sys.bf_read_phys({}));
            bsl::discard(m_sys.bf_virt_to_phys({}));
            bsl::discard(m_sys.bf_phys_to_virt({}));

            return true;
        }

        [[nodiscard]] constexpr auto
        test_member_nonconst() noexcept -> bool
        {
            bf_uint64_t phys{};

            bsl::discard(bf_syscall_t{});
            bsl::discard(m_sys.initialize({}, {}, {}, {}));
            m_sys.release();
            bsl::discard(m_sys.bf_tls_rax());
            m_sys.bf_tls_set_rax({});
            bsl::discard(m_sys.bf_tls_rbx());
            m_sys.bf_tls_set_rbx({});
            bsl::discard(m_sys.bf_tls_rcx());
            m_sys.bf_tls_set_rcx({});
            bsl::discard(m_sys.bf_tls_rdx());
            m_sys.bf_tls_set_rdx({});
            bsl::discard(m_sys.bf_tls_rbp());
            m_sys.bf_tls_set_rbp({});
            bsl::discard(m_sys.bf_tls_rsi());
            m_sys.bf_tls_set_rsi({});
            bsl::discard(m_sys.bf_tls_rdi());
            m_sys.bf_tls_set_rdi({});
            bsl::discard(m_sys.bf_tls_r8());
            m_sys.bf_tls_set_r8({});
            bsl::discard(m_sys.bf_tls_r9());
            m_sys.bf_tls_set_r9({});
            bsl::discard(m_sys.bf_tls_r10());
            m_sys.bf_tls_set_r10({});
            bsl::discard(m_sys.bf_tls_r11());
            m_sys.bf_tls_set_r11({});
            bsl::discard(m_sys.bf_tls_r12());
            m_sys.bf_tls_set_r12({});
            bsl::discard(m_sys.bf_tls_r13());
            m_sys.bf_tls_set_r13({});
            bsl::discard(m_sys.bf_tls_r14());
            m_sys.bf_tls_set_r14({});
            bsl::discard(m_sys.bf_tls_r15());
            m_sys.bf_tls_set_r15({});
            bsl::discard(m_sys.bf_tls_extid());
            bsl::discard(m_sys.bf_tls_vmid());
            bsl::discard(m_sys.bf_tls_vpid());
            bsl::discard(m_sys.bf_tls_vpsid());
            bsl::discard(m_sys.bf_tls_ppid());
            bsl::discard(m_sys.bf_tls_online_pps());
            bsl::discard(m_sys.bf_vm_op_create_vm());
            bsl::discard(m_sys.bf_vm_op_destroy_vm({}));
            bsl::discard(m_sys.bf_vp_op_create_vp({}, {}));
            bsl::discard(m_sys.bf_vp_op_destroy_vp({}));
            bsl::discard(m_sys.bf_vp_op_migrate({}, {}));
            bsl::discard(m_sys.bf_vps_op_create_vps({}, {}));
            bsl::discard(m_sys.bf_vps_op_destroy_vps({}));
            bsl::discard(m_sys.bf_vps_op_init_as_root({}));
            bsl::discard(m_sys.bf_vps_op_read8({}, {}));
            bsl::discard(m_sys.bf_vps_op_read16({}, {}));
            bsl::discard(m_sys.bf_vps_op_read32({}, {}));
            bsl::discard(m_sys.bf_vps_op_read64({}, {}));
            bsl::discard(m_sys.bf_vps_op_write8({}, {}, {}));
            bsl::discard(m_sys.bf_vps_op_write16({}, {}, {}));
            bsl::discard(m_sys.bf_vps_op_write32({}, {}, {}));
            bsl::discard(m_sys.bf_vps_op_write64({}, {}, {}));
            bsl::discard(m_sys.bf_vps_op_read_reg({}, {}));
            bsl::discard(m_sys.bf_vps_op_write_reg({}, {}, {}));
            bsl::discard(m_sys.bf_vps_op_run({}, {}, {}));
            bsl::discard(m_sys.bf_vps_op_run_current());
            bsl::discard(m_sys.bf_vps_op_advance_ip({}));
            bsl::discard(m_sys.bf_vps_op_advance_ip_and_run_current());
            bsl::discard(m_sys.bf_vps_op_promote({}));
            bsl::discard(m_sys.bf_vps_op_clear_vps({}));
            bsl::discard(m_sys.bf_intrinsic_op_rdmsr({}));
            bsl::discard(m_sys.bf_intrinsic_op_wrmsr({}, {}));
            bsl::discard(m_sys.bf_intrinsic_op_invlpga({}, {}));
            bsl::discard(m_sys.bf_intrinsic_op_invept({}, {}));
            bsl::discard(m_sys.bf_intrinsic_op_invvpid({}, {}, {}));
            bsl::discard(m_sys.bf_mem_op_alloc_page(phys));
            bsl::discard(m_sys.bf_mem_op_alloc_page());
            bsl::discard(m_sys.bf_mem_op_free_page({}));
            bsl::discard(m_sys.bf_mem_op_alloc_huge({}, phys));
            bsl::discard(m_sys.bf_mem_op_alloc_huge({}));
            bsl::discard(m_sys.bf_mem_op_free_huge({}));
            bsl::discard(m_sys.bf_mem_op_alloc_heap({}));
            bsl::discard(m_sys.bf_read_phys({}));
            bsl::discard(m_sys.bf_write_phys({}, {}));
            bsl::discard(m_sys.bf_virt_to_phys({}));
            bsl::discard(m_sys.bf_phys_to_virt({}));

            return true;
        }
    };

    constexpr fixture_t FIXTURE1{};
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
    bsl::ut_scenario{"verify supports constinit"} = []() noexcept {
        bsl::discard(syscall::g_verify_constinit);
    };

    bsl::ut_scenario{"verify noexcept"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            syscall::bf_syscall_t sys{};
            syscall::bf_uint64_t phys{};
            bsl::ut_then{} = []() noexcept {
                static_assert(noexcept(syscall::bf_syscall_t{}));
                static_assert(noexcept(sys.initialize({}, {}, {}, {})));
                static_assert(noexcept(sys.release()));
                static_assert(noexcept(sys.bf_tls_rax()));
                static_assert(noexcept(sys.bf_tls_set_rax({})));
                static_assert(noexcept(sys.bf_tls_rbx()));
                static_assert(noexcept(sys.bf_tls_set_rbx({})));
                static_assert(noexcept(sys.bf_tls_rcx()));
                static_assert(noexcept(sys.bf_tls_set_rcx({})));
                static_assert(noexcept(sys.bf_tls_rdx()));
                static_assert(noexcept(sys.bf_tls_set_rdx({})));
                static_assert(noexcept(sys.bf_tls_rbp()));
                static_assert(noexcept(sys.bf_tls_set_rbp({})));
                static_assert(noexcept(sys.bf_tls_rsi()));
                static_assert(noexcept(sys.bf_tls_set_rsi({})));
                static_assert(noexcept(sys.bf_tls_rdi()));
                static_assert(noexcept(sys.bf_tls_set_rdi({})));
                static_assert(noexcept(sys.bf_tls_r8()));
                static_assert(noexcept(sys.bf_tls_set_r8({})));
                static_assert(noexcept(sys.bf_tls_r9()));
                static_assert(noexcept(sys.bf_tls_set_r9({})));
                static_assert(noexcept(sys.bf_tls_r10()));
                static_assert(noexcept(sys.bf_tls_set_r10({})));
                static_assert(noexcept(sys.bf_tls_r11()));
                static_assert(noexcept(sys.bf_tls_set_r11({})));
                static_assert(noexcept(sys.bf_tls_r12()));
                static_assert(noexcept(sys.bf_tls_set_r12({})));
                static_assert(noexcept(sys.bf_tls_r13()));
                static_assert(noexcept(sys.bf_tls_set_r13({})));
                static_assert(noexcept(sys.bf_tls_r14()));
                static_assert(noexcept(sys.bf_tls_set_r14({})));
                static_assert(noexcept(sys.bf_tls_r15()));
                static_assert(noexcept(sys.bf_tls_set_r15({})));
                static_assert(noexcept(sys.bf_tls_extid()));
                static_assert(noexcept(sys.bf_tls_vmid()));
                static_assert(noexcept(sys.bf_tls_vpid()));
                static_assert(noexcept(sys.bf_tls_vpsid()));
                static_assert(noexcept(sys.bf_tls_ppid()));
                static_assert(noexcept(sys.bf_tls_online_pps()));
                static_assert(noexcept(sys.bf_vm_op_create_vm()));
                static_assert(noexcept(sys.bf_vm_op_destroy_vm({})));
                static_assert(noexcept(sys.bf_vp_op_create_vp({}, {})));
                static_assert(noexcept(sys.bf_vp_op_destroy_vp({})));
                static_assert(noexcept(sys.bf_vp_op_migrate({}, {})));
                static_assert(noexcept(sys.bf_vps_op_create_vps({}, {})));
                static_assert(noexcept(sys.bf_vps_op_destroy_vps({})));
                static_assert(noexcept(sys.bf_vps_op_init_as_root({})));
                static_assert(noexcept(sys.bf_vps_op_read8({}, {})));
                static_assert(noexcept(sys.bf_vps_op_read16({}, {})));
                static_assert(noexcept(sys.bf_vps_op_read32({}, {})));
                static_assert(noexcept(sys.bf_vps_op_read64({}, {})));
                static_assert(noexcept(sys.bf_vps_op_write8({}, {}, {})));
                static_assert(noexcept(sys.bf_vps_op_write16({}, {}, {})));
                static_assert(noexcept(sys.bf_vps_op_write32({}, {}, {})));
                static_assert(noexcept(sys.bf_vps_op_write64({}, {}, {})));
                static_assert(noexcept(sys.bf_vps_op_read_reg({}, {})));
                static_assert(noexcept(sys.bf_vps_op_write_reg({}, {}, {})));
                static_assert(noexcept(sys.bf_vps_op_run({}, {}, {})));
                static_assert(noexcept(sys.bf_vps_op_run_current()));
                static_assert(noexcept(sys.bf_vps_op_advance_ip({})));
                static_assert(noexcept(sys.bf_vps_op_advance_ip_and_run_current()));
                static_assert(noexcept(sys.bf_vps_op_promote({})));
                static_assert(noexcept(sys.bf_vps_op_clear_vps({})));
                static_assert(noexcept(sys.bf_intrinsic_op_rdmsr({})));
                static_assert(noexcept(sys.bf_intrinsic_op_wrmsr({}, {})));
                static_assert(noexcept(sys.bf_intrinsic_op_invlpga({}, {})));
                static_assert(noexcept(sys.bf_intrinsic_op_invept({}, {})));
                static_assert(noexcept(sys.bf_intrinsic_op_invvpid({}, {}, {})));
                static_assert(noexcept(sys.bf_mem_op_alloc_page(phys)));
                static_assert(noexcept(sys.bf_mem_op_alloc_page()));
                static_assert(noexcept(sys.bf_mem_op_free_page({})));
                static_assert(noexcept(sys.bf_mem_op_alloc_huge({}, phys)));
                static_assert(noexcept(sys.bf_mem_op_alloc_huge({})));
                static_assert(noexcept(sys.bf_mem_op_free_huge({})));
                static_assert(noexcept(sys.bf_mem_op_alloc_heap({})));
                static_assert(noexcept(sys.bf_read_phys({})));
                static_assert(noexcept(sys.bf_write_phys({}, {})));
                static_assert(noexcept(sys.bf_virt_to_phys({})));
                static_assert(noexcept(sys.bf_phys_to_virt({})));
            };
        };
    };

    bsl::ut_scenario{"verify constness"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            syscall::fixture_t fixture2{};
            bsl::ut_then{} = [&]() noexcept {
                bsl::ut_check(syscall::FIXTURE1.test_member_const());
                bsl::ut_check(fixture2.test_member_nonconst());
            };
        };
    };

    return bsl::ut_success();
}
