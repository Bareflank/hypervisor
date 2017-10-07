//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

#include <bfgsl.h>
#include <bfdebug.h>
#include <bfconstants.h>
#include <bfthreadcontext.h>

#include <memory_manager/memory_manager_x64.h>

#include <vmcs/vmcs_intel_x64.h>
#include <vmcs/vmcs_intel_x64_launch.h>
#include <vmcs/vmcs_intel_x64_resume.h>
#include <vmcs/vmcs_intel_x64_promote.h>

#include <intrinsics/x86/intel_x64.h>
#include <intrinsics/x86/common_x64.h>

using namespace x64;
using namespace intel_x64;
using namespace vmcs;

void
vmcs_intel_x64::launch(gsl::not_null<vmcs_intel_x64_state *> host_state,
                       gsl::not_null<vmcs_intel_x64_state *> guest_state)
{
    this->create_vmcs_region();

    auto ___ = gsl::on_failure([&] {
        this->release_vmcs_region();
    });

    this->create_exit_handler_stack();

    auto ___ = gsl::on_failure([&] {
        this->release_exit_handler_stack();
    });

    this->clear();
    this->load();
    this->write_fields(host_state, guest_state);

    auto ___ = gsl::on_failure([&] {
        bfdebug_transaction(0, [&](std::string * msg)
        { vmcs::debug::dump(0, msg); });
    });

    auto ___ = gsl::on_failure([&] {
        vmcs::check::all();
    });

    if (guest_state->is_guest()) {
        vmcs_launch(m_state_save);
        throw std::runtime_error("vmcs resume failed");
    }
    else {
        vm::launch_demote();
    }
}

void
vmcs_intel_x64::promote(gsl::not_null<const void *> guest_gdt)
{
    vmcs_promote(m_state_save, guest_gdt);
    throw std::runtime_error("vmcs promote failed");
}

void
vmcs_intel_x64::resume()
{
    vmcs_resume(m_state_save);
    throw std::runtime_error("vmcs resume failed");
}

void
vmcs_intel_x64::load()
{
    vm::load(&m_vmcs_region_phys);
    bfdebug_nhex(1, "loaded vmcs region", m_vmcs_region_phys);
}

void
vmcs_intel_x64::clear()
{
    vm::clear(&m_vmcs_region_phys);
    bfdebug_nhex(1, "cleared vmcs region", m_vmcs_region_phys);
}

void
vmcs_intel_x64::create_vmcs_region()
{
    auto ___ = gsl::on_failure([&]
    { this->release_vmcs_region(); });

    m_vmcs_region = std::make_unique<uint32_t[]>(1024);
    m_vmcs_region_phys = g_mm->virtptr_to_physint(m_vmcs_region.get());

    gsl::span<uint32_t> id{m_vmcs_region.get(), 1024};
    id[0] = gsl::narrow<uint32_t>(intel_x64::msrs::ia32_vmx_basic::revision_id::get());

    bfdebug_transaction(1, [&](std::string * msg) {
        bfdebug_pass(1, "create vmcs region", msg);
        bfdebug_subnhex(1, "virt address", m_vmcs_region.get(), msg);
        bfdebug_subnhex(1, "phys address", m_vmcs_region_phys, msg);
    });
}

void
vmcs_intel_x64::release_vmcs_region() noexcept
{
    bfdebug_transaction(1, [&](std::string * msg) {
        bfdebug_pass(1, "release vmcs region", msg);
        bfdebug_subnhex(1, "virt address", m_vmcs_region.get(), msg);
        bfdebug_subnhex(1, "phys address", m_vmcs_region_phys, msg);
    });

    m_vmcs_region.reset();
    m_vmcs_region_phys = 0;
}

void
vmcs_intel_x64::create_exit_handler_stack()
{
    auto size = STACK_SIZE * 2;
    m_exit_handler_stack = std::make_unique<gsl::byte[]>(size);

    bfdebug_transaction(1, [&](std::string * msg) {
        bfdebug_pass(1, "create vmm stack", msg);
        bfdebug_subnhex(1, "size", size, msg);
        bfdebug_subnhex(1, "addr", m_exit_handler_stack.get(), msg);
    });
}

void
vmcs_intel_x64::release_exit_handler_stack() noexcept
{
    bfdebug_transaction(1, [&](std::string * msg) {
        bfdebug_pass(1, "release vmm stack", msg);
        bfdebug_subnhex(1, "addr", m_exit_handler_stack.get(), msg);
    });

    m_exit_handler_stack.reset();
}

void
vmcs_intel_x64::write_fields(gsl::not_null<vmcs_intel_x64_state *> host_state,
                             gsl::not_null<vmcs_intel_x64_state *> guest_state)
{
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
}

void
vmcs_intel_x64::write_16bit_control_state(gsl::not_null<vmcs_intel_x64_state *> state)
{
    (void) state;

    // unused: VMCS_VIRTUAL_PROCESSOR_IDENTIFIER
    // unused: VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR
    // unused: VMCS_EPTP_INDEX

    bfdebug_pass(1, "write 16bit control state");
}

void
vmcs_intel_x64::write_64bit_control_state(gsl::not_null<vmcs_intel_x64_state *> state)
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

    bfdebug_pass(1, "write 64bit control state");
}

void
vmcs_intel_x64::write_32bit_control_state(gsl::not_null<vmcs_intel_x64_state *> state)
{
    (void) state;

    intel_x64::msrs::value_type lower;
    intel_x64::msrs::value_type upper;

    auto ia32_vmx_pinbased_ctls_msr = intel_x64::msrs::ia32_vmx_true_pinbased_ctls::get();
    auto ia32_vmx_procbased_ctls_msr = intel_x64::msrs::ia32_vmx_true_procbased_ctls::get();
    auto ia32_vmx_exit_ctls_msr = intel_x64::msrs::ia32_vmx_true_exit_ctls::get();
    auto ia32_vmx_entry_ctls_msr = intel_x64::msrs::ia32_vmx_true_entry_ctls::get();

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

    bfdebug_transaction(1, [&](std::string * msg) {
        bfdebug_pass(1, "write 32bit control state", msg);
        bfdebug_subnhex(1, "ia32_vmx_pinbased_ctls_msr", ia32_vmx_pinbased_ctls_msr, msg);
        bfdebug_subnhex(1, "ia32_vmx_procbased_ctls_msr", ia32_vmx_procbased_ctls_msr, msg);
        bfdebug_subnhex(1, "ia32_vmx_exit_ctls_msr", ia32_vmx_exit_ctls_msr, msg);
        bfdebug_subnhex(1, "ia32_vmx_entry_ctls_msr", ia32_vmx_entry_ctls_msr, msg);
    });
}

void
vmcs_intel_x64::write_natural_control_state(gsl::not_null<vmcs_intel_x64_state *> state)
{
    (void) state;

    // unused: VMCS_CR0_GUEST_HOST_MASK
    // unused: VMCS_CR4_GUEST_HOST_MASK
    // unused: VMCS_CR0_READ_SHADOW
    // unused: VMCS_CR4_READ_SHADOW
    // unused: VMCS_CR3_TARGET_VALUE_0
    // unused: VMCS_CR3_TARGET_VALUE_1
    // unused: VMCS_CR3_TARGET_VALUE_2
    // unused: VMCS_CR3_TARGET_VALUE_3

    bfdebug_pass(1, "write natural width control state");
}

void
vmcs_intel_x64::write_16bit_guest_state(gsl::not_null<vmcs_intel_x64_state *> state)
{
    auto es = state->es();
    auto cs = state->cs();
    auto ss = state->ss();
    auto ds = state->ds();
    auto fs = state->fs();
    auto gs = state->gs();
    auto ldtr = state->ldtr();
    auto tr = state->tr();

    vmcs::guest_es_selector::set(es);
    vmcs::guest_cs_selector::set(cs);
    vmcs::guest_ss_selector::set(ss);
    vmcs::guest_ds_selector::set(ds);
    vmcs::guest_fs_selector::set(fs);
    vmcs::guest_gs_selector::set(gs);
    vmcs::guest_ldtr_selector::set(ldtr);
    vmcs::guest_tr_selector::set(tr);

    // unused: VMCS_GUEST_INTERRUPT_STATUS

    bfdebug_transaction(1, [&](std::string * msg) {
        bfdebug_pass(1, "write 16bit guest state", msg);
        bfdebug_subnhex(1, "es", es, msg);
        bfdebug_subnhex(1, "cs", cs, msg);
        bfdebug_subnhex(1, "ss", ss, msg);
        bfdebug_subnhex(1, "ds", ds, msg);
        bfdebug_subnhex(1, "fs", fs, msg);
        bfdebug_subnhex(1, "gs", gs, msg);
        bfdebug_subnhex(1, "ldtr", ldtr, msg);
        bfdebug_subnhex(1, "tr", tr, msg);
    });
}

void
vmcs_intel_x64::write_64bit_guest_state(gsl::not_null<vmcs_intel_x64_state *> state)
{
    auto link_pointer = 0xFFFFFFFFFFFFFFFF;
    auto ia32_debugctl_msr = state->ia32_debugctl_msr();
    auto ia32_pat_msr = state->ia32_pat_msr();
    auto ia32_efer_msr = state->ia32_efer_msr();
    auto ia32_perf_global_ctrl_msr = state->ia32_perf_global_ctrl_msr();

    vmcs::vmcs_link_pointer::set(link_pointer);
    vmcs::guest_ia32_debugctl::set(ia32_debugctl_msr);
    vmcs::guest_ia32_pat::set(ia32_pat_msr);
    vmcs::guest_ia32_efer::set(ia32_efer_msr);
    vmcs::guest_ia32_perf_global_ctrl::set_if_exists(ia32_perf_global_ctrl_msr);

    // unused: VMCS_GUEST_PDPTE0
    // unused: VMCS_GUEST_PDPTE1
    // unused: VMCS_GUEST_PDPTE2
    // unused: VMCS_GUEST_PDPTE3

    bfdebug_transaction(1, [&](std::string * msg) {
        bfdebug_pass(1, "write 64bit guest state", msg);
        bfdebug_subnhex(1, "vmcs link pointer", link_pointer, msg);
        bfdebug_subnhex(1, "ia32_debugctl_msr", ia32_debugctl_msr, msg);
        bfdebug_subnhex(1, "ia32_pat_msr", ia32_pat_msr, msg);
        bfdebug_subnhex(1, "ia32_efer_msr", ia32_efer_msr, msg);
        bfdebug_subnhex(1, "ia32_perf_global_ctrl_msr", ia32_perf_global_ctrl_msr, msg);
    });
}

void
vmcs_intel_x64::write_32bit_guest_state(gsl::not_null<vmcs_intel_x64_state *> state)
{
    auto es_limit = state->es_limit();
    auto cs_limit = state->cs_limit();
    auto ss_limit = state->ss_limit();
    auto ds_limit = state->ds_limit();
    auto fs_limit = state->fs_limit();
    auto gs_limit = state->gs_limit();
    auto ldtr_limit = state->ldtr_limit();
    auto tr_limit = state->tr_limit();

    vmcs::guest_es_limit::set(es_limit);
    vmcs::guest_cs_limit::set(cs_limit);
    vmcs::guest_ss_limit::set(ss_limit);
    vmcs::guest_ds_limit::set(ds_limit);
    vmcs::guest_fs_limit::set(fs_limit);
    vmcs::guest_gs_limit::set(gs_limit);
    vmcs::guest_ldtr_limit::set(ldtr_limit);
    vmcs::guest_tr_limit::set(tr_limit);

    auto gdt_limit = state->gdt_limit();
    auto idt_limit = state->idt_limit();

    vmcs::guest_gdtr_limit::set(gdt_limit);
    vmcs::guest_idtr_limit::set(idt_limit);

    auto es_access_rights = state->es_access_rights();
    auto cs_access_rights = state->cs_access_rights();
    auto ss_access_rights = state->ss_access_rights();
    auto ds_access_rights = state->ds_access_rights();
    auto fs_access_rights = state->fs_access_rights();
    auto gs_access_rights = state->gs_access_rights();
    auto ldtr_access_rights = state->ldtr_access_rights();
    auto tr_access_rights = state->tr_access_rights();

    vmcs::guest_es_access_rights::set(es_access_rights);
    vmcs::guest_cs_access_rights::set(cs_access_rights);
    vmcs::guest_ss_access_rights::set(ss_access_rights);
    vmcs::guest_ds_access_rights::set(ds_access_rights);
    vmcs::guest_fs_access_rights::set(fs_access_rights);
    vmcs::guest_gs_access_rights::set(gs_access_rights);
    vmcs::guest_ldtr_access_rights::set(ldtr_access_rights);
    vmcs::guest_tr_access_rights::set(tr_access_rights);

    auto ia32_sysenter_cs_msr = state->ia32_sysenter_cs_msr();

    vmcs::guest_ia32_sysenter_cs::set(ia32_sysenter_cs_msr);

    // unused: VMCS_GUEST_INTERRUPTIBILITY_STATE
    // unused: VMCS_GUEST_ACTIVITY_STATE
    // unused: VMCS_GUEST_SMBASE
    // unused: VMCS_VMX_PREEMPTION_TIMER_VALUE

    bfdebug_transaction(1, [&](std::string * msg) {
        bfdebug_pass(1, "write 32bit guest state", msg);
        bfdebug_subnhex(1, "es limit", es_limit, msg);
        bfdebug_subnhex(1, "cs limit", cs_limit, msg);
        bfdebug_subnhex(1, "ss limit", ss_limit, msg);
        bfdebug_subnhex(1, "ds limit", ds_limit, msg);
        bfdebug_subnhex(1, "fs limit", fs_limit, msg);
        bfdebug_subnhex(1, "gs limit", gs_limit, msg);
        bfdebug_subnhex(1, "ldtr limit", ldtr_limit, msg);
        bfdebug_subnhex(1, "tr limit", tr_limit, msg);
        bfdebug_subnhex(1, "gdt limit", gdt_limit, msg);
        bfdebug_subnhex(1, "idt limit", idt_limit, msg);
        bfdebug_subnhex(1, "es access rights", es_access_rights, msg);
        bfdebug_subnhex(1, "cs access rights", cs_access_rights, msg);
        bfdebug_subnhex(1, "ss access rights", ss_access_rights, msg);
        bfdebug_subnhex(1, "ds access rights", ds_access_rights, msg);
        bfdebug_subnhex(1, "fs access rights", fs_access_rights, msg);
        bfdebug_subnhex(1, "gs access rights", gs_access_rights, msg);
        bfdebug_subnhex(1, "ldtr access rights", ldtr_access_rights, msg);
        bfdebug_subnhex(1, "tr access rights", tr_access_rights, msg);
        bfdebug_subnhex(1, "sysenter cs msr", ia32_sysenter_cs_msr, msg);
    });
}

void
vmcs_intel_x64::write_natural_guest_state(gsl::not_null<vmcs_intel_x64_state *> state)
{
    auto cr0 = state->cr0();
    auto cr3 = state->cr3();
    auto cr4 = state->cr4();

    vmcs::guest_cr0::set(cr0);
    vmcs::guest_cr3::set(cr3);
    vmcs::guest_cr4::set(cr4);

    auto es_base = state->es_base();
    auto cs_base = state->cs_base();
    auto ss_base = state->ss_base();
    auto ds_base = state->ds_base();
    auto fs_base = state->ia32_fs_base_msr();
    auto gs_base = state->ia32_gs_base_msr();
    auto ldtr_base = state->ldtr_base();
    auto tr_base = state->tr_base();

    vmcs::guest_es_base::set(es_base);
    vmcs::guest_cs_base::set(cs_base);
    vmcs::guest_ss_base::set(ss_base);
    vmcs::guest_ds_base::set(ds_base);
    vmcs::guest_fs_base::set(fs_base);
    vmcs::guest_gs_base::set(gs_base);
    vmcs::guest_ldtr_base::set(ldtr_base);
    vmcs::guest_tr_base::set(tr_base);

    auto gdt_base = state->gdt_base();
    auto idt_base = state->idt_base();

    vmcs::guest_gdtr_base::set(gdt_base);
    vmcs::guest_idtr_base::set(idt_base);

    auto dr7 = state->dr7();
    auto rflags = state->rflags();

    vmcs::guest_dr7::set(dr7);
    vmcs::guest_rflags::set(rflags);

    auto ia32_sysenter_esp_msr = state->ia32_sysenter_esp_msr();
    auto ia32_sysenter_eip_msr = state->ia32_sysenter_eip_msr();

    vmcs::guest_ia32_sysenter_esp::set(ia32_sysenter_esp_msr);
    vmcs::guest_ia32_sysenter_eip::set(ia32_sysenter_eip_msr);

    // unused: VMCS_GUEST_RSP, see m_intrinsics->vmlaunch()
    // unused: VMCS_GUEST_RIP, see m_intrinsics->vmlaunch()
    // unused: VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS

    bfdebug_transaction(1, [&](std::string * msg) {
        bfdebug_pass(1, "write natural width guest state", msg);
        bfdebug_subnhex(1, "cr0", cr0, msg);
        bfdebug_subnhex(1, "cr3", cr3, msg);
        bfdebug_subnhex(1, "cr4", cr4, msg);
        bfdebug_subnhex(1, "es base", es_base, msg);
        bfdebug_subnhex(1, "cs base", cs_base, msg);
        bfdebug_subnhex(1, "ss base", ss_base, msg);
        bfdebug_subnhex(1, "ds base", ds_base, msg);
        bfdebug_subnhex(1, "fs base", fs_base, msg);
        bfdebug_subnhex(1, "gs base", gs_base, msg);
        bfdebug_subnhex(1, "ldtr base", ldtr_base, msg);
        bfdebug_subnhex(1, "tr base", tr_base, msg);
        bfdebug_subnhex(1, "gdt base", gdt_base, msg);
        bfdebug_subnhex(1, "idt base", idt_base, msg);
        bfdebug_subnhex(1, "dr7", dr7, msg);
        bfdebug_subnhex(1, "rflags", rflags, msg);
        bfdebug_subnhex(1, "ia32_sysenter_esp_msr", ia32_sysenter_esp_msr, msg);
        bfdebug_subnhex(1, "ia32_sysenter_eip_msr", ia32_sysenter_eip_msr, msg);
    });
}

void
vmcs_intel_x64::write_16bit_host_state(gsl::not_null<vmcs_intel_x64_state *> state)
{
    auto es = state->es();
    auto cs = state->cs();
    auto ss = state->ss();
    auto ds = state->ds();
    auto fs = state->fs();
    auto gs = state->gs();
    auto tr = state->tr();

    vmcs::host_es_selector::set(es);
    vmcs::host_cs_selector::set(cs);
    vmcs::host_ss_selector::set(ss);
    vmcs::host_ds_selector::set(ds);
    vmcs::host_fs_selector::set(fs);
    vmcs::host_gs_selector::set(gs);
    vmcs::host_tr_selector::set(tr);

    bfdebug_transaction(1, [&](std::string * msg) {
        bfdebug_pass(1, "write 16bit host state", msg);
        bfdebug_subnhex(1, "es", es, msg);
        bfdebug_subnhex(1, "cs", cs, msg);
        bfdebug_subnhex(1, "ss", ss, msg);
        bfdebug_subnhex(1, "ds", ds, msg);
        bfdebug_subnhex(1, "fs", fs, msg);
        bfdebug_subnhex(1, "gs", gs, msg);
        bfdebug_subnhex(1, "tr", tr, msg);
    });
}

void
vmcs_intel_x64::write_64bit_host_state(gsl::not_null<vmcs_intel_x64_state *> state)
{
    auto ia32_pat_msr = state->ia32_pat_msr();
    auto ia32_efer_msr = state->ia32_efer_msr();
    auto ia32_perf_global_ctrl_msr = state->ia32_perf_global_ctrl_msr();

    vmcs::host_ia32_pat::set(ia32_pat_msr);
    vmcs::host_ia32_efer::set(ia32_efer_msr);
    vmcs::host_ia32_perf_global_ctrl::set_if_exists(ia32_perf_global_ctrl_msr);

    bfdebug_transaction(1, [&](std::string * msg) {
        bfdebug_pass(1, "write 64bit host state", msg);
        bfdebug_subnhex(1, "ia32_pat_msr", ia32_pat_msr, msg);
        bfdebug_subnhex(1, "ia32_efer_msr", ia32_efer_msr, msg);
        bfdebug_subnhex(1, "ia32_perf_global_ctrl_msr", ia32_perf_global_ctrl_msr, msg);
    });
}

void
vmcs_intel_x64::write_32bit_host_state(gsl::not_null<vmcs_intel_x64_state *> state)
{
    auto ia32_sysenter_cs_msr = state->ia32_sysenter_cs_msr();

    vmcs::host_ia32_sysenter_cs::set(ia32_sysenter_cs_msr);

    bfdebug_transaction(1, [&](std::string * msg) {
        bfdebug_pass(1, "write 32bit host state", msg);
        bfdebug_subnhex(1, "ia32_sysenter_cs_msr", ia32_sysenter_cs_msr, msg);
    });
}

void
vmcs_intel_x64::write_natural_host_state(gsl::not_null<vmcs_intel_x64_state *> state)
{
    auto cr0 = state->cr0();
    auto cr3 = state->cr3();
    auto cr4 = state->cr4();

    vmcs::host_cr0::set(cr0);
    vmcs::host_cr3::set(cr3);
    vmcs::host_cr4::set(cr4);

    auto fs_base = state->ia32_fs_base_msr();
    auto gs_base = reinterpret_cast<uintptr_t>(m_state_save);
    auto tr_base = state->tr_base();

    vmcs::host_fs_base::set(fs_base);
    vmcs::host_gs_base::set(gs_base);
    vmcs::host_tr_base::set(tr_base);

    auto gdt_base = state->gdt_base();
    auto idt_base = state->idt_base();

    vmcs::host_gdtr_base::set(gdt_base);
    vmcs::host_idtr_base::set(idt_base);

    auto ia32_sysenter_esp_msr = state->ia32_sysenter_esp_msr();
    auto ia32_sysenter_eip_msr = state->ia32_sysenter_eip_msr();

    vmcs::host_ia32_sysenter_esp::set(ia32_sysenter_esp_msr);
    vmcs::host_ia32_sysenter_eip::set(ia32_sysenter_eip_msr);

    auto exit_handler_stack = setup_stack(m_exit_handler_stack.get());
    auto exit_handler_entry = reinterpret_cast<uintptr_t>(m_exit_handler_entry);

    vmcs::host_rsp::set(exit_handler_stack);
    vmcs::host_rip::set(exit_handler_entry);

    bfdebug_transaction(1, [&](std::string * msg) {
        bfdebug_pass(1, "write natural width host state", msg);
        bfdebug_subnhex(1, "cr0", cr0, msg);
        bfdebug_subnhex(1, "cr3", cr3, msg);
        bfdebug_subnhex(1, "cr4", cr4, msg);
        bfdebug_subnhex(1, "fs base", fs_base, msg);
        bfdebug_subnhex(1, "gs base", gs_base, msg);
        bfdebug_subnhex(1, "tr base", tr_base, msg);
        bfdebug_subnhex(1, "gdt base", gdt_base, msg);
        bfdebug_subnhex(1, "idt base", idt_base, msg);
        bfdebug_subnhex(1, "ia32_sysenter_esp_msr", ia32_sysenter_esp_msr, msg);
        bfdebug_subnhex(1, "ia32_sysenter_eip_msr", ia32_sysenter_eip_msr, msg);
        bfdebug_subnhex(1, "exit_handler_stack", exit_handler_stack, msg);
        bfdebug_subnhex(1, "exit_handler_entry", exit_handler_entry, msg);
    });
}

void
vmcs_intel_x64::pin_based_vm_execution_controls()
{
    // pin_based_vm_execution_controls::external_interrupt_exiting::enable_if_allowed();
    // pin_based_vm_execution_controls::nmi_exiting::enable_if_allowed();
    // pin_based_vm_execution_controls::virtual_nmis::enable_if_allowed();
    // pin_based_vm_execution_controls::activate_vmx_preemption_timer::enable_if_allowed();
    // pin_based_vm_execution_controls::process_posted_interrupts::enable_if_allowed();

    bfdebug_transaction(1, [&](std::string * msg) {
        pin_based_vm_execution_controls::dump(1, msg);
    });
}

void
vmcs_intel_x64::primary_processor_based_vm_execution_controls()
{
    // primary_processor_based_vm_execution_controls::interrupt_window_exiting::enable_if_allowed();
    // primary_processor_based_vm_execution_controls::use_tsc_offsetting::enable_if_allowed();
    // primary_processor_based_vm_execution_controls::hlt_exiting::enable_if_allowed();
    // primary_processor_based_vm_execution_controls::invlpg_exiting::enable_if_allowed();
    // primary_processor_based_vm_execution_controls::mwait_exiting::enable_if_allowed();
    // primary_processor_based_vm_execution_controls::rdpmc_exiting::enable_if_allowed();
    // primary_processor_based_vm_execution_controls::rdtsc_exiting::enable_if_allowed();
    // primary_processor_based_vm_execution_controls::cr3_load_exiting::enable_if_allowed();
    // primary_processor_based_vm_execution_controls::cr3_store_exiting::enable_if_allowed();
    // primary_processor_based_vm_execution_controls::cr8_load_exiting::enable_if_allowed();
    // primary_processor_based_vm_execution_controls::cr8_store_exiting::enable_if_allowed();
    // primary_processor_based_vm_execution_controls::use_tpr_shadow::enable_if_allowed();
    // primary_processor_based_vm_execution_controls::nmi_window_exiting::enable_if_allowed();
    // primary_processor_based_vm_execution_controls::mov_dr_exiting::enable_if_allowed();
    // primary_processor_based_vm_execution_controls::unconditional_io_exiting::enable_if_allowed();
    // primary_processor_based_vm_execution_controls::use_io_bitmaps::enable_if_allowed();
    // primary_processor_based_vm_execution_controls::monitor_trap_flag::enable_if_allowed();
    // primary_processor_based_vm_execution_controls::use_msr_bitmaps::enable_if_allowed();
    // primary_processor_based_vm_execution_controls::monitor_exiting::enable_if_allowed();
    // primary_processor_based_vm_execution_controls::pause_exiting::enable_if_allowed();
    primary_processor_based_vm_execution_controls::activate_secondary_controls::enable_if_allowed();

    bfdebug_transaction(1, [&](std::string * msg) {
        primary_processor_based_vm_execution_controls::dump(1, msg);
    });
}

void
vmcs_intel_x64::secondary_processor_based_vm_execution_controls()
{
    // secondary_processor_based_vm_execution_controls::virtualize_apic_accesses::enable_if_allowed();
    // secondary_processor_based_vm_execution_controls::enable_ept::enable_if_allowed();
    // secondary_processor_based_vm_execution_controls::descriptor_table_exiting::enable_if_allowed();
    secondary_processor_based_vm_execution_controls::enable_rdtscp::enable_if_allowed();
    // secondary_processor_based_vm_execution_controls::virtualize_x2apic_mode::enable_if_allowed();
    // secondary_processor_based_vm_execution_controls::enable_vpid::enable_if_allowed();
    // secondary_processor_based_vm_execution_controls::wbinvd_exiting::enable_if_allowed();
    // secondary_processor_based_vm_execution_controls::unrestricted_guest::enable_if_allowed();
    // secondary_processor_based_vm_execution_controls::apic_register_virtualization::enable_if_allowed();
    // secondary_processor_based_vm_execution_controls::virtual_interrupt_delivery::enable_if_allowed();
    // secondary_processor_based_vm_execution_controls::pause_loop_exiting::enable_if_allowed();
    // secondary_processor_based_vm_execution_controls::rdrand_exiting::enable_if_allowed();
    secondary_processor_based_vm_execution_controls::enable_invpcid::enable_if_allowed();
    // secondary_processor_based_vm_execution_controls::enable_vm_functions::enable_if_allowed();
    // secondary_processor_based_vm_execution_controls::vmcs_shadowing::enable_if_allowed();
    // secondary_processor_based_vm_execution_controls::rdseed_exiting::enable_if_allowed();
    // secondary_processor_based_vm_execution_controls::ept_violation_ve::enable_if_allowed();
    secondary_processor_based_vm_execution_controls::enable_xsaves_xrstors::enable_if_allowed();

    bfdebug_transaction(1, [&](std::string * msg) {
        secondary_processor_based_vm_execution_controls::dump(1, msg);
    });
}

void
vmcs_intel_x64::vm_exit_controls()
{
    vm_exit_controls::save_debug_controls::enable_if_allowed();
    vm_exit_controls::host_address_space_size::enable_if_allowed();
    vm_exit_controls::load_ia32_perf_global_ctrl::enable_if_allowed();
    // vm_exit_controls::acknowledge_interrupt_on_exit::enable_if_allowed();
    vm_exit_controls::save_ia32_pat::enable_if_allowed();
    vm_exit_controls::load_ia32_pat::enable_if_allowed();
    vm_exit_controls::save_ia32_efer::enable_if_allowed();
    vm_exit_controls::load_ia32_efer::enable_if_allowed();
    // vm_exit_controls::save_vmx_preemption_timer_value::enable_if_allowed();

    bfdebug_transaction(1, [&](std::string * msg) {
        vm_exit_controls::dump(1, msg);
    });
}

void
vmcs_intel_x64::vm_entry_controls()
{
    vm_entry_controls::load_debug_controls::enable_if_allowed();
    vm_entry_controls::ia_32e_mode_guest::enable_if_allowed();
    // vm_entry_controls::entry_to_smm::enable_if_allowed();
    // vm_entry_controls::deactivate_dual_monitor_treatment::enable_if_allowed();
    vm_entry_controls::load_ia32_perf_global_ctrl::enable_if_allowed();
    vm_entry_controls::load_ia32_pat::enable_if_allowed();
    vm_entry_controls::load_ia32_efer::enable_if_allowed();

    bfdebug_transaction(1, [&](std::string * msg) {
        vm_entry_controls::dump(1, msg);
    });
}
