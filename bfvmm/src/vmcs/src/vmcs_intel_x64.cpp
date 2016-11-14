//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include <gsl/gsl>

#include <debug.h>
#include <constants.h>
#include <thread_context.h>
#include <vmcs/vmcs_intel_x64.h>
#include <vmcs/vmcs_intel_x64_32bit_control_fields.h>
#include <vmcs/vmcs_intel_x64_resume.h>
#include <vmcs/vmcs_intel_x64_promote.h>
#include <vmcs/vmcs_intel_x64_16bit_host_state_fields.h>
#include <vmcs/vmcs_intel_x64_16bit_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_32bit_guest_state_fields.h>
#include <memory_manager/memory_manager_x64.h>
#include <exit_handler/exit_handler_intel_x64_support.h>

using namespace x64;
using namespace intel_x64;
using namespace vmcs;

vmcs_intel_x64::vmcs_intel_x64() : m_vmcs_region_phys(0)
{
}

void
vmcs_intel_x64::launch(const std::shared_ptr<vmcs_intel_x64_state> &host_state,
                       const std::shared_ptr<vmcs_intel_x64_state> &guest_state)
{
    this->create_vmcs_region();

    auto ___ = gsl::on_failure([&]
    { this->release_vmcs_region(); });

    this->create_exit_handler_stack();

    auto ___ = gsl::on_failure([&]
    { this->release_exit_handler_stack(); });

    this->clear();
    this->load();

    this->write_16bit_guest_state(guest_state);
    this->write_64bit_guest_state(guest_state);
    this->write_32bit_guest_state(guest_state);
    this->write_natural_guest_state(guest_state);

    this->write_16bit_control_state(host_state);
    this->write_64bit_control_state(host_state);
    this->write_32bit_control_state(host_state);
    this->write_natural_control_state(host_state);

    this->write_16bit_host_state(host_state);
    this->write_64bit_host_state(host_state);
    this->write_32bit_host_state(host_state);
    this->write_natural_host_state(host_state);

    this->pin_based_vm_execution_controls();
    this->primary_processor_based_vm_execution_controls();
    this->secondary_processor_based_vm_execution_controls();
    this->vm_exit_controls();
    this->vm_entry_controls();

    auto ___ = gsl::on_failure([&]
    {
        // this->dump_vmcs();

        // this->print_execution_controls();
        // this->print_pin_based_vm_execution_controls();
        // this->print_primary_processor_based_vm_execution_controls();
        // this->print_secondary_processor_based_vm_execution_controls();
        // this->print_vm_exit_control_fields();
        // this->print_vm_entry_control_fields();

        // host_state->dump();
        // guest_state->dump();
    });

    auto ___ = gsl::on_failure([&]
    {
        this->check_vmcs_control_state();
        this->check_vmcs_guest_state();
        this->check_vmcs_host_state();
    });

    vm::launch();
}

void
vmcs_intel_x64::promote()
{
    vmcs_promote(vm::read(VMCS_HOST_GS_BASE));

    throw std::runtime_error("vmcs promote failed");
}

void
vmcs_intel_x64::resume()
{
    vmcs_resume(m_state_save.get());

    throw std::runtime_error("vmcs resume failed");
}

void
vmcs_intel_x64::load()
{
    vm::load(&m_vmcs_region_phys);
}

void
vmcs_intel_x64::clear()
{
    vm::clear(&m_vmcs_region_phys);
}

void
vmcs_intel_x64::create_vmcs_region()
{
    auto ___ = gsl::on_failure([&]
    { this->release_vmcs_region(); });

    m_vmcs_region = std::make_unique<uint32_t[]>(1024);
    m_vmcs_region_phys = g_mm->virtptr_to_physint(m_vmcs_region.get());

    gsl::span<uint32_t> id{m_vmcs_region.get(), 1024};
    id[0] = gsl::narrow<uint32_t>(msrs::ia32_vmx_basic::revision_id::get());
}

void
vmcs_intel_x64::release_vmcs_region() noexcept
{
    m_vmcs_region.reset();
    m_vmcs_region_phys = 0;
}

void
vmcs_intel_x64::create_exit_handler_stack()
{
    m_exit_handler_stack = std::make_unique<char[]>(STACK_SIZE * 2);
}

void
vmcs_intel_x64::release_exit_handler_stack() noexcept
{
    m_exit_handler_stack.reset();
}

void
vmcs_intel_x64::write_16bit_control_state(const std::shared_ptr<vmcs_intel_x64_state> &state)
{
    (void) state;

    // unused: VMCS_VIRTUAL_PROCESSOR_IDENTIFIER
    // unused: VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR
    // unused: VMCS_EPTP_INDEX
}

void
vmcs_intel_x64::write_64bit_control_state(const std::shared_ptr<vmcs_intel_x64_state> &state)
{
    (void) state;

    // unused: VMCS_ADDRESS_OF_IO_BITMAP_A
    // unused: VMCS_ADDRESS_OF_IO_BITMAP_B
    // unused: VMCS_ADDRESS_OF_MSR_BITMAPS
    // unused: VMCS_VM_EXIT_MSR_STORE_ADDRESS
    // unused: VMCS_VM_EXIT_MSR_LOAD_ADDRESS
    // unused: VMCS_VM_ENTRY_MSR_LOAD_ADDRESS
    // unused: VMCS_EXECUTIVE_VMCS_POINTER
    // unused: VMCS_TSC_OFFSET
    // unused: VMCS_VIRTUAL_APIC_ADDRESS
    // unused: VMCS_APIC_ACCESS_ADDRESS
    // unused: VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS
    // unused: VMCS_VM_FUNCTION_CONTROLS
    // unused: VMCS_EPT_POINTER
    // unused: VMCS_EOI_EXIT_BITMAP_0
    // unused: VMCS_EOI_EXIT_BITMAP_1
    // unused: VMCS_EOI_EXIT_BITMAP_2
    // unused: VMCS_EOI_EXIT_BITMAP_3
    // unused: VMCS_EPTP_LIST_ADDRESS
    // unused: VMCS_VMREAD_BITMAP_ADDRESS
    // unused: VMCS_VMWRITE_BITMAP_ADDRESS
    // unused: VMCS_VIRTUALIZATION_EXCEPTION_INFORMATION_ADDRESS
    // unused: VMCS_XSS_EXITING_BITMAP
}

void
vmcs_intel_x64::write_32bit_control_state(const std::shared_ptr<vmcs_intel_x64_state> &state)
{
    (void) state;

    uint64_t lower;
    uint64_t upper;

    auto ia32_vmx_pinbased_ctls_msr = msrs::ia32_vmx_true_pinbased_ctls::get();
    auto ia32_vmx_procbased_ctls_msr = msrs::ia32_vmx_true_procbased_ctls::get();
    auto ia32_vmx_exit_ctls_msr = msrs::ia32_vmx_true_exit_ctls::get();
    auto ia32_vmx_entry_ctls_msr = msrs::ia32_vmx_true_entry_ctls::get();

    lower = ((ia32_vmx_pinbased_ctls_msr >> 0) & 0x00000000FFFFFFFF);
    upper = ((ia32_vmx_pinbased_ctls_msr >> 32) & 0x00000000FFFFFFFF);
    pin_based_vm_execution_controls::set(lower & upper);

    lower = ((ia32_vmx_procbased_ctls_msr >> 0) & 0x00000000FFFFFFFF);
    upper = ((ia32_vmx_procbased_ctls_msr >> 32) & 0x00000000FFFFFFFF);
    primary_processor_based_vm_execution_controls::set(lower & upper);

    lower = ((ia32_vmx_exit_ctls_msr >> 0) & 0x00000000FFFFFFFF);
    upper = ((ia32_vmx_exit_ctls_msr >> 32) & 0x00000000FFFFFFFF);
    vm_exit_controls::set(lower & upper);

    lower = ((ia32_vmx_entry_ctls_msr >> 0) & 0x00000000FFFFFFFF);
    upper = ((ia32_vmx_entry_ctls_msr >> 32) & 0x00000000FFFFFFFF);
    vm_entry_controls::set(lower & upper);

    // unused: VMCS_EXCEPTION_BITMAP
    // unused: VMCS_PAGE_FAULT_ERROR_CODE_MASK
    // unused: VMCS_PAGE_FAULT_ERROR_CODE_MATCH
    // unused: VMCS_CR3_TARGET_COUNT
    // unused: VMCS_VM_EXIT_MSR_STORE_COUNT
    // unused: VMCS_VM_EXIT_MSR_LOAD_COUNT
    // unused: VMCS_VM_ENTRY_MSR_LOAD_COUNT
    // unused: VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD
    // unused: VMCS_VM_ENTRY_EXCEPTION_ERROR_CODE
    // unused: VMCS_VM_ENTRY_INSTRUCTION_LENGTH
    // unused: VMCS_TPR_THRESHOLD
    // unused: VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS
    // unused: VMCS_PLE_GAP
    // unused: VMCS_PLE_WINDOW
}

void
vmcs_intel_x64::write_natural_control_state(const std::shared_ptr<vmcs_intel_x64_state> &state)
{
    (void) state;

    // unused: VMCS_CR0_GUEST_HOST_MASK
    // unused: VMCS_CR4_GUEST_HOST_MASK
    // unused: VMCS_CR0_READ_SHADOW
    // unused: VMCS_CR4_READ_SHADOW
    // unused: VMCS_CR3_TARGET_VALUE_0
    // unused: VMCS_CR3_TARGET_VALUE_1
    // unused: VMCS_CR3_TARGET_VALUE_2
    // unused: VMCS_CR3_TARGET_VALUE_31
}

void
vmcs_intel_x64::write_16bit_guest_state(const std::shared_ptr<vmcs_intel_x64_state> &state)
{
    vmcs::guest_es_selector::set(state->es());
    vmcs::guest_cs_selector::set(state->cs());
    vmcs::guest_ss_selector::set(state->ss());
    vmcs::guest_ds_selector::set(state->ds());
    vmcs::guest_fs_selector::set(state->fs());
    vmcs::guest_gs_selector::set(state->gs());
    vmcs::guest_ldtr_selector::set(state->ldtr());
    vmcs::guest_tr_selector::set(state->tr());

    // unused: VMCS_GUEST_INTERRUPT_STATUS
}

void
vmcs_intel_x64::write_64bit_guest_state(const std::shared_ptr<vmcs_intel_x64_state> &state)
{
    vm::write(VMCS_VMCS_LINK_POINTER, 0xFFFFFFFFFFFFFFFF);
    vmcs::guest_ia32_debugctl::set(state->ia32_debugctl_msr());
    vm::write(VMCS_GUEST_IA32_PAT, state->ia32_pat_msr());
    vmcs::guest_ia32_efer::set(state->ia32_efer_msr());
    vm::write(VMCS_GUEST_IA32_PERF_GLOBAL_CTRL, state->ia32_perf_global_ctrl_msr());

    // unused: VMCS_GUEST_PDPTE0
    // unused: VMCS_GUEST_PDPTE1
    // unused: VMCS_GUEST_PDPTE2
    // unused: VMCS_GUEST_PDPTE3
}

void
vmcs_intel_x64::write_32bit_guest_state(const std::shared_ptr<vmcs_intel_x64_state> &state)
{
    vmcs::guest_es_limit::set(state->es_limit());
    vmcs::guest_cs_limit::set(state->cs_limit());
    vmcs::guest_ss_limit::set(state->ss_limit());
    vmcs::guest_ds_limit::set(state->ds_limit());
    vmcs::guest_fs_limit::set(state->fs_limit());
    vmcs::guest_gs_limit::set(state->gs_limit());
    vmcs::guest_ldtr_limit::set(state->ldtr_limit());
    vmcs::guest_tr_limit::set(state->tr_limit());

    vmcs::guest_gdtr_limit::set(state->gdt_limit());
    vmcs::guest_idtr_limit::set(state->idt_limit());

    vmcs::guest_es_access_rights::set(state->es_access_rights());
    vmcs::guest_cs_access_rights::set(state->cs_access_rights());
    vmcs::guest_ss_access_rights::set(state->ss_access_rights());
    vmcs::guest_ds_access_rights::set(state->ds_access_rights());
    vmcs::guest_fs_access_rights::set(state->fs_access_rights());
    vmcs::guest_gs_access_rights::set(state->gs_access_rights());
    vmcs::guest_ldtr_access_rights::set(state->ldtr_access_rights());
    vmcs::guest_tr_access_rights::set(state->tr_access_rights());

    vmcs::guest_ia32_sysenter_cs::set(state->ia32_sysenter_cs_msr());

    // unused: VMCS_GUEST_INTERRUPTIBILITY_STATE
    // unused: VMCS_GUEST_ACTIVITY_STATE
    // unused: VMCS_GUEST_SMBASE
    // unused: VMCS_VMX_PREEMPTION_TIMER_VALUE
}

void
vmcs_intel_x64::write_natural_guest_state(const std::shared_ptr<vmcs_intel_x64_state> &state)
{
    vmcs::guest_cr0::set(state->cr0());
    vmcs::guest_cr3::set(state->cr3());
    vmcs::guest_cr4::set(state->cr4());

    vm::write(VMCS_GUEST_ES_BASE, state->es_base());
    vm::write(VMCS_GUEST_CS_BASE, state->cs_base());
    vm::write(VMCS_GUEST_SS_BASE, state->ss_base());
    vm::write(VMCS_GUEST_DS_BASE, state->ds_base());
    vm::write(VMCS_GUEST_FS_BASE, state->ia32_fs_base_msr());
    vm::write(VMCS_GUEST_GS_BASE, state->ia32_gs_base_msr());
    vm::write(VMCS_GUEST_LDTR_BASE, state->ldtr_base());
    vm::write(VMCS_GUEST_TR_BASE, state->tr_base());

    vm::write(VMCS_GUEST_GDTR_BASE, state->gdt_base());
    vm::write(VMCS_GUEST_IDTR_BASE, state->idt_base());

    vm::write(VMCS_GUEST_DR7, state->dr7());
    vmcs::guest_rflags::set(state->rflags());

    vm::write(VMCS_GUEST_IA32_SYSENTER_ESP, state->ia32_sysenter_esp_msr());
    vm::write(VMCS_GUEST_IA32_SYSENTER_EIP, state->ia32_sysenter_eip_msr());

    // unused: VMCS_GUEST_RSP, see m_intrinsics->vmlaunch()
    // unused: VMCS_GUEST_RIP, see m_intrinsics->vmlaunch()
    // unused: VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS
}

void
vmcs_intel_x64::write_16bit_host_state(const std::shared_ptr<vmcs_intel_x64_state> &state)
{
    vmcs::host_es_selector::set(state->es());
    vmcs::host_cs_selector::set(state->cs());
    vmcs::host_ss_selector::set(state->ss());
    vmcs::host_ds_selector::set(state->ds());
    vmcs::host_fs_selector::set(state->fs());
    vmcs::host_gs_selector::set(state->gs());
    vmcs::host_tr_selector::set(state->tr());
}

void
vmcs_intel_x64::write_64bit_host_state(const std::shared_ptr<vmcs_intel_x64_state> &state)
{
    vm::write(VMCS_HOST_IA32_PAT, state->ia32_pat_msr());
    vmcs::host_ia32_efer::set(state->ia32_efer_msr());
    vm::write(VMCS_HOST_IA32_PERF_GLOBAL_CTRL, state->ia32_perf_global_ctrl_msr());
}

void
vmcs_intel_x64::write_32bit_host_state(const std::shared_ptr<vmcs_intel_x64_state> &state)
{
    vm::write(VMCS_HOST_IA32_SYSENTER_CS, state->ia32_sysenter_cs_msr());
}

void
vmcs_intel_x64::write_natural_host_state(const std::shared_ptr<vmcs_intel_x64_state> &state)
{
    auto exit_handler_stack = reinterpret_cast<uintptr_t>(m_exit_handler_stack.get());

    auto stack_top = exit_handler_stack + (STACK_SIZE * 2);
    stack_top = (stack_top & ~(STACK_SIZE - 1)) - 1;
    exit_handler_stack = stack_top - sizeof(thread_context_t) - 1;

    auto tc = reinterpret_cast<thread_context_t *>(stack_top - sizeof(thread_context_t));
    tc->cpuid = thread_context_cpuid();
    tc->tlsptr = thread_context_tlsptr();

    vmcs::host_cr0::set(state->cr0());
    vmcs::host_cr3::set(state->cr3());
    vmcs::host_cr4::set(state->cr4());

    vm::write(VMCS_HOST_FS_BASE, state->ia32_fs_base_msr());
    vm::write(VMCS_HOST_GS_BASE, reinterpret_cast<uintptr_t>(m_state_save.get()));
    vm::write(VMCS_HOST_TR_BASE, state->tr_base());

    vm::write(VMCS_HOST_GDTR_BASE, state->gdt_base());
    vm::write(VMCS_HOST_IDTR_BASE, state->idt_base());

    vm::write(VMCS_HOST_IA32_SYSENTER_ESP, state->ia32_sysenter_esp_msr());
    vm::write(VMCS_HOST_IA32_SYSENTER_EIP, state->ia32_sysenter_eip_msr());

    vm::write(VMCS_HOST_RSP, reinterpret_cast<uintptr_t>(exit_handler_stack));
    vm::write(VMCS_HOST_RIP, reinterpret_cast<uintptr_t>(exit_handler_entry));
}

void
vmcs_intel_x64::pin_based_vm_execution_controls()
{
    // pin_based_vm_execution_controls::external_interrupt_exiting::enable();
    // pin_based_vm_execution_controls::nmi_exiting::enable();
    // pin_based_vm_execution_controls::virtual_nmis::enable();
    // pin_based_vm_execution_controls::activate_vmx_preemption_timer::enable();
    // pin_based_vm_execution_controls::process_posted_interrupts::enable();
}

void
vmcs_intel_x64::primary_processor_based_vm_execution_controls()
{
    // primary_processor_based_vm_execution_controls::interrupt_window_exiting::enable();
    // primary_processor_based_vm_execution_controls::use_tsc_offsetting::enable();
    // primary_processor_based_vm_execution_controls::hlt_exiting::enable();
    // primary_processor_based_vm_execution_controls::invlpg_exiting::enable();
    // primary_processor_based_vm_execution_controls::mwait_exiting::enable();
    // primary_processor_based_vm_execution_controls::rdpmc_exiting::enable();
    // primary_processor_based_vm_execution_controls::rdtsc_exiting::enable();
    // primary_processor_based_vm_execution_controls::cr3_load_exiting::enable();
    // primary_processor_based_vm_execution_controls::cr3_store_exiting::enable();
    // primary_processor_based_vm_execution_controls::cr8_load_exiting::enable();
    // primary_processor_based_vm_execution_controls::cr8_store_exiting::enable();
    // primary_processor_based_vm_execution_controls::use_tpr_shadow::enable();
    // primary_processor_based_vm_execution_controls::nmi_window_exiting::enable();
    // primary_processor_based_vm_execution_controls::mov_dr_exiting::enable();
    // primary_processor_based_vm_execution_controls::unconditional_io_exiting::enable();
    // primary_processor_based_vm_execution_controls::use_io_bitmaps::enable();
    // primary_processor_based_vm_execution_controls::monitor_trap_flag::enable();
    // primary_processor_based_vm_execution_controls::use_msr_bitmaps::enable();
    // primary_processor_based_vm_execution_controls::monitor_exiting::enable();
    // primary_processor_based_vm_execution_controls::pause_exiting::enable();
    primary_processor_based_vm_execution_controls::activate_secondary_controls::enable();
}

void
vmcs_intel_x64::secondary_processor_based_vm_execution_controls()
{
    bool verbose = true;

    // secondary_processor_based_vm_execution_controls::virtualize_apic_accesses::enable_if_allowed(verbose);
    // secondary_processor_based_vm_execution_controls::enable_ept::enable_if_allowed(verbose);
    // secondary_processor_based_vm_execution_controls::descriptor_table_exiting::enable_if_allowed(verbose);
    secondary_processor_based_vm_execution_controls::enable_rdtscp::enable_if_allowed(verbose);
    // secondary_processor_based_vm_execution_controls::virtualize_x2apic_mode::enable_if_allowed(verbose);
    // secondary_processor_based_vm_execution_controls::enable_vpid::enable_if_allowed(verbose);
    // secondary_processor_based_vm_execution_controls::wbinvd_exiting::enable_if_allowed(verbose);
    // secondary_processor_based_vm_execution_controls::unrestricted_guest::enable_if_allowed(verbose);
    // secondary_processor_based_vm_execution_controls::apic_register_virtualization::enable_if_allowed(verbose);
    // secondary_processor_based_vm_execution_controls::virtual_interrupt_delivery::enable_if_allowed(verbose);
    // secondary_processor_based_vm_execution_controls::pause_loop_exiting::enable_if_allowed(verbose);
    // secondary_processor_based_vm_execution_controls::rdrand_exiting::enable_if_allowed(verbose);
    secondary_processor_based_vm_execution_controls::enable_invpcid::enable_if_allowed(verbose);
    // secondary_processor_based_vm_execution_controls::enable_vm_functions::enable_if_allowed(verbose);
    // secondary_processor_based_vm_execution_controls::vmcs_shadowing::enable_if_allowed(verbose);
    // secondary_processor_based_vm_execution_controls::rdseed_exiting::enable_if_allowed(verbose);
    // secondary_processor_based_vm_execution_controls::ept_violation_ve::enable_if_allowed(verbose);
    secondary_processor_based_vm_execution_controls::enable_xsaves_xrstors::enable_if_allowed(verbose);
}

void
vmcs_intel_x64::vm_exit_controls()
{
    vm_exit_controls::save_debug_controls::enable();
    vm_exit_controls::host_address_space_size::enable();
    vm_exit_controls::load_ia32_perf_global_ctrl::enable();
    vm_exit_controls::acknowledge_interrupt_on_exit::enable();
    vm_exit_controls::save_ia32_pat::enable();
    vm_exit_controls::load_ia32_pat::enable();
    vm_exit_controls::save_ia32_efer::enable();
    vm_exit_controls::load_ia32_efer::enable();
    // vm_exit_controls::save_vmx_preemption_timer_value::enable();
}

void
vmcs_intel_x64::vm_entry_controls()
{
    vm_entry_controls::load_debug_controls::enable();
    vm_entry_controls::ia_32e_mode_guest::enable();
    // vm_entry_controls::entry_to_smm::enable();
    // vm_entry_controls::deactivate_dual_monitor_treatment::enable();
    vm_entry_controls::load_ia32_perf_global_ctrl::enable();
    vm_entry_controls::load_ia32_pat::enable();
    vm_entry_controls::load_ia32_efer::enable();
}
