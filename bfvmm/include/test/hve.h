//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

/// @cond

#ifdef BF_X64

#include "../hve/arch/x64/gdt.h"
#include "../hve/arch/x64/idt.h"

std::vector<bfvmm::x64::gdt::segment_descriptor_type> g_gdt = {
    0x0,
    0xFF7FFFFFFFFFFFFF,
    0xFF7FFFFFFFFFFFFF,
    0xFF7FFFFFFFFFFFFF,
    0xFF7FFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFF8FFFFFFFFFFF,
    0x00000000FFFFFFFF,
};

std::vector<bfvmm::x64::idt::interrupt_descriptor_type> g_idt = {
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF
};

void
setup_gdt_x64()
{
    auto limit = g_gdt.size() * sizeof(bfvmm::x64::gdt::segment_descriptor_type) - 1;

    g_gdtr.base = reinterpret_cast<uint64_t>(&g_gdt.at(0));
    g_gdtr.limit = gsl::narrow_cast<uint16_t>(limit);
}

void
setup_idt_x64()
{
    auto limit = g_idt.size() * sizeof(bfvmm::x64::idt::interrupt_descriptor_type) - 1;

    g_idtr.base = reinterpret_cast<uint64_t>(&g_idt.at(0));
    g_idtr.limit = gsl::narrow_cast<uint16_t>(limit);
}

#endif

#ifdef BF_INTEL_X64

#include <hippomocks.h>

#include "../hve/arch/intel_x64/vmx.h"
#include "../hve/arch/intel_x64/vmcs.h"
#include "../hve/arch/intel_x64/check.h"
#include "../hve/arch/intel_x64/exception.h"
#include "../hve/arch/intel_x64/vcpu.h"
#include <bftypes.h>

bfvmm::intel_x64::save_state_t g_save_state{};

extern "C" void vmcs_launch(
    bfvmm::intel_x64::save_state_t *save_state) noexcept
{ bfignored(save_state); }

extern "C" void vmcs_promote(
    bfvmm::intel_x64::save_state_t *save_state, const void *gdt) noexcept
{ bfignored(save_state); bfignored(gdt); }

extern "C" void vmcs_resume(
    bfvmm::intel_x64::save_state_t *save_state) noexcept
{ bfignored(save_state); }

extern "C" void vmexit_entry(void)
{ }

auto
setup_vcpu(MockRepository &mocks, ::intel_x64::vmcs::value_type reason = 0)
{
    auto vcpu = mocks.Mock<bfvmm::intel_x64::vcpu>();

    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::run);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::hlt);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::init);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::fini);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::id).Return(0);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::is_running).Return(false);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::is_initialized).Return(false);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::is_bootstrap_vcpu).Return(true);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::is_host_vm_vcpu).Return(true);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::is_guest_vm_vcpu).Return(false);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::add_run_delegate);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::add_hlt_delegate);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::add_init_delegate);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::add_fini_delegate);

    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::run_delegate);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::hlt_delegate);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::add_handler);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::add_exit_handler);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::dump);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::halt);

    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::advance).Do([&] {
        g_save_state.rip = 42;
        return true;
    });

    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_eptp);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::disable_ept);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::enable_vpid);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::disable_vpid);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::trap_on_msr_access);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::pass_through_msr_access);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::add_wrcr0_handler);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::add_rdcr3_handler);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::add_wrcr3_handler);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::add_wrcr4_handler);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::add_cpuid_handler);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::emulate_cpuid);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::add_default_cpuid_handler);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::add_ept_misconfiguration_handler);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::add_ept_read_violation_handler);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::add_ept_write_violation_handler);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::add_ept_execute_violation_handler);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::add_default_ept_read_violation_handler);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::add_default_ept_write_violation_handler);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::add_default_ept_execute_violation_handler);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::add_external_interrupt_handler);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::disable_external_interrupts);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::queue_external_interrupt);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::inject_exception);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::inject_external_interrupt);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::trap_on_all_io_instruction_accesses);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::pass_through_all_io_instruction_accesses);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::pass_through_io_accesses);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::add_io_instruction_handler);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::emulate_io_instruction);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::add_default_io_instruction_handler);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::add_monitor_trap_handler);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::enable_monitor_trap_flag);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::trap_on_rdmsr_access);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::trap_on_all_rdmsr_accesses);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::pass_through_rdmsr_access);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::pass_through_all_rdmsr_accesses);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::add_rdmsr_handler);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::emulate_rdmsr);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::add_default_rdmsr_handler);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::trap_on_wrmsr_access);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::trap_on_all_wrmsr_accesses);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::pass_through_wrmsr_access);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::pass_through_all_wrmsr_accesses);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::add_wrmsr_handler);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::emulate_wrmsr);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::add_default_wrmsr_handler);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::add_xsetbv_handler);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::add_preemption_timer_handler);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_preemption_timer);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::get_preemption_timer).Return(0);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::enable_preemption_timer);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::disable_preemption_timer);

    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::rax).Do([&] { return g_save_state.rax; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_rax).Do([&](uint64_t val) { g_save_state.rax = val; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::rbx).Do([&] { return g_save_state.rbx; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_rbx).Do([&](uint64_t val) { g_save_state.rbx = val; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::rcx).Do([&] { return g_save_state.rcx; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_rcx).Do([&](uint64_t val) { g_save_state.rcx = val; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::rdx).Do([&] { return g_save_state.rdx; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_rdx).Do([&](uint64_t val) { g_save_state.rdx = val; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::rbp).Do([&] { return g_save_state.rbp; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_rbp).Do([&](uint64_t val) { g_save_state.rbp = val; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::rsi).Do([&] { return g_save_state.rsi; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_rsi).Do([&](uint64_t val) { g_save_state.rsi = val; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::rdi).Do([&] { return g_save_state.rdi; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_rdi).Do([&](uint64_t val) { g_save_state.rdi = val; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::r08).Do([&] { return g_save_state.r08; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_r08).Do([&](uint64_t val) { g_save_state.r08 = val; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::r09).Do([&] { return g_save_state.r09; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_r09).Do([&](uint64_t val) { g_save_state.r09 = val; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::r10).Do([&] { return g_save_state.r10; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_r10).Do([&](uint64_t val) { g_save_state.r10 = val; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::r11).Do([&] { return g_save_state.r11; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_r11).Do([&](uint64_t val) { g_save_state.r11 = val; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::r12).Do([&] { return g_save_state.r12; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_r12).Do([&](uint64_t val) { g_save_state.r12 = val; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::r13).Do([&] { return g_save_state.r13; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_r13).Do([&](uint64_t val) { g_save_state.r13 = val; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::r14).Do([&] { return g_save_state.r14; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_r14).Do([&](uint64_t val) { g_save_state.r14 = val; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::r15).Do([&] { return g_save_state.r15; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_r15).Do([&](uint64_t val) { g_save_state.r15 = val; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::rip).Do([&] { return g_save_state.rip; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_rip).Do([&](uint64_t val) { g_save_state.rip = val; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::rsp).Do([&] { return g_save_state.rsp; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_rsp).Do([&](uint64_t val) { g_save_state.rsp = val; });
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::gdt_base);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_gdt_base);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::gdt_limit);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_gdt_limit);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::idt_base);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_idt_base);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::idt_limit);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_idt_limit);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::cr0);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_cr0);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::cr3);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_cr3);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::cr4);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_cr4);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::ia32_efer);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_ia32_efer);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::ia32_pat);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_ia32_pat);

    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::es_selector);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_es_selector);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::es_base);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_es_base);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::es_limit);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_es_limit);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::es_access_rights);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_es_access_rights);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::cs_selector);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_cs_selector);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::cs_base);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_cs_base);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::cs_limit);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_cs_limit);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::cs_access_rights);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_cs_access_rights);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::ss_selector);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_ss_selector);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::ss_base);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_ss_base);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::ss_limit);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_ss_limit);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::ss_access_rights);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_ss_access_rights);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::ds_selector);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_ds_selector);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::ds_base);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_ds_base);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::ds_limit);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_ds_limit);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::ds_access_rights);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_ds_access_rights);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::fs_selector);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_fs_selector);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::fs_base);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_fs_base);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::fs_limit);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_fs_limit);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::fs_access_rights);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_fs_access_rights);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::gs_selector);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_gs_selector);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::gs_base);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_gs_base);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::gs_limit);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_gs_limit);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::gs_access_rights);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_gs_access_rights);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::tr_selector);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_tr_selector);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::tr_base);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_tr_base);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::tr_limit);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_tr_limit);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::tr_access_rights);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_tr_access_rights);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::ldtr_selector);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_ldtr_selector);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::ldtr_base);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_ldtr_base);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::ldtr_limit);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_ldtr_limit);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::ldtr_access_rights);
    mocks.OnCall(vcpu, bfvmm::intel_x64::vcpu::set_ldtr_access_rights);

    g_vmcs_fields[::intel_x64::vmcs::exit_reason::addr] = reason;
    g_vmcs_fields[::intel_x64::vmcs::vm_exit_instruction_length::addr] = 42;

    g_eax_cpuid[intel_x64::cpuid::arch_perf_monitoring::addr] = 0xFFFFFFFF;
    g_ecx_cpuid[intel_x64::cpuid::feature_information::addr] = 0xFFFFFFFF;
    g_ebx_cpuid[intel_x64::cpuid::extended_feature_flags::addr] = 0xFFFFFFFF;

    return vcpu;
}

#endif

bool vmm_main(vcpu_t vcpu)
{ return true; }

bool vmm_fini(vcpu_t vcpu)
{ return true; }


/// @endcond
