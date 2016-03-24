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

#include <debug.h>
#include <constants.h>
#include <commit_or_rollback.h>
#include <vmcs/vmcs_intel_x64.h>
#include <vmcs/vmcs_intel_x64_exceptions.h>
#include <exit_handler/exit_handler_intel_x64_support.h>
#include <memory_manager/memory_manager.h>

vmcs_intel_x64::vmcs_intel_x64(const std::shared_ptr<intrinsics_intel_x64> &intrinsics) :
    m_msr_bitmap(4096 * 8),
    m_intrinsics(intrinsics)
{
    if (!m_intrinsics)
        throw invalid_argument(intrinsics, "intrinsics == null");

    m_msr_bitmap_phys = m_msr_bitmap.phys_addr();
}

void
vmcs_intel_x64::launch(const vmcs_state_intel_x64 &host_state,
                       const vmcs_state_intel_x64 &guest_state)
{
    if (this->is_supported_msr_bitmaps() == false)
        throw hardware_unsupported("msr bitmaps required");

    if (this->is_supported_host_address_space_size() == false)
        throw hardware_unsupported("64bit host support required");

    if (this->is_supported_ia_32e_mode_guest() == false)
        throw hardware_unsupported("64bit guest support required");

    auto cor1 = commit_or_rollback([&]
    {
        this->release_vmcs_region();
        this->release_exit_handler_stack();
    });

    this->create_vmcs_region();
    this->create_exit_handler_stack();

    if (m_intrinsics->vmclear(&m_vmcs_region_phys) == false)
        throw vmcs_failure("failed to clear vmcs");

    if (m_intrinsics->vmptrld(&m_vmcs_region_phys) == false)
        throw vmcs_failure("failed to load vmcs");

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

    this->default_pin_based_vm_execution_controls();
    this->default_primary_processor_based_vm_execution_controls();
    this->default_secondary_processor_based_vm_execution_controls();
    this->default_vm_exit_controls();
    this->default_vm_entry_controls();

    if (m_intrinsics->vmlaunch() == false)
    {
        this->dump_vmcs();

        this->print_execution_controls();
        this->print_pin_based_vm_execution_controls();
        this->print_primary_processor_based_vm_execution_controls();
        this->print_secondary_processor_based_vm_execution_controls();
        this->print_vm_exit_control_fields();
        this->print_vm_entry_control_fields();

        host_state.dump("Host");
        guest_state.dump("Guest");

        this->check_vmcs_control_state();
        this->check_vmcs_guest_state();
        this->check_vmcs_host_state();

        throw vmcs_launch_failure(this->get_vm_instruction_error());
    }

    cor1.commit();
}

void
vmcs_intel_x64::promote()
{
    auto cor1 = commit_or_rollback([&]
    {
        bffatal << "promote failed. unable to rollback state" << bfendl;
        abort();
    });

    this->promote_16bit_guest_state();
    this->promote_32bit_guest_state();
    this->promote_64bit_guest_state();
    this->promote_natural_guest_state();

    promote_vmcs_to_root();
}

void
vmcs_intel_x64::create_vmcs_region()
{
    auto cor1 = commit_or_rollback([&]
    { this->release_vmcs_region(); });

    auto region = (uint32_t *)g_mm->malloc_aligned(4096, 4096);

    m_vmcs_region = std::unique_ptr<uint32_t>(region);
    m_vmcs_region_phys = (uintptr_t)g_mm->virt_to_phys(region);

    if (((uintptr_t)region & 0x0000000000000FFF) != 0)
        throw invalid_alignmnet(
            "vmxon region not page aligned", (uintptr_t)region);

    region[0] = m_intrinsics->read_msr(IA32_VMX_BASIC_MSR) & 0x7FFFFFFFF;

    cor1.commit();
}

void
vmcs_intel_x64::release_vmcs_region()
{
    if (m_vmcs_region_phys != 0)
    {
        if (m_intrinsics->vmclear(&m_vmcs_region_phys) == false)
            throw vmcs_failure("failed to clear vmcs");

        m_vmcs_region.reset();
        m_vmcs_region_phys = 0;
    }
}

void
vmcs_intel_x64::create_exit_handler_stack()
{
    auto cor1 = commit_or_rollback([&]
    { this->release_exit_handler_stack(); });

    m_exit_handler_stack = std::make_unique<char[]>(STACK_SIZE);

    cor1.commit();
}

void
vmcs_intel_x64::release_exit_handler_stack()
{
    m_exit_handler_stack.reset();
}

void
vmcs_intel_x64::write_16bit_control_state(const vmcs_state_intel_x64 &state)
{
    (void) state;

    // unused: VMCS_VIRTUAL_PROCESSOR_IDENTIFIER
    // unused: VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR
    // unused: VMCS_EPTP_INDEX
}

void
vmcs_intel_x64::write_64bit_control_state(const vmcs_state_intel_x64 &state)
{
    (void) state;

    vmwrite(VMCS_ADDRESS_OF_MSR_BITMAPS_FULL, m_msr_bitmap_phys);

    // unused: VMCS_ADDRESS_OF_IO_BITMAP_A_FULL
    // unused: VMCS_ADDRESS_OF_IO_BITMAP_B_FULL
    // unused: VMCS_VM_EXIT_MSR_STORE_ADDRESS_FULL
    // unused: VMCS_VM_EXIT_MSR_LOAD_ADDRESS_FULL
    // unused: VMCS_VM_ENTRY_MSR_LOAD_ADDRESS_FULL
    // unused: VMCS_EXECUTIVE_VMCS_POINTER_FULL
    // unused: VMCS_TSC_OFFSET_FULL
    // unused: VMCS_VIRTUAL_APIC_ADDRESS_FULL
    // unused: VMCS_APIC_ACCESS_ADDRESS_FULL
    // unused: VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_FULL
    // unused: VMCS_VM_FUNCTION_CONTROLS_FULL
    // unused: VMCS_EPT_POINTER_FULL
    // unused: VMCS_EOI_EXIT_BITMAP_0_FULL
    // unused: VMCS_EOI_EXIT_BITMAP_1_FULL
    // unused: VMCS_EOI_EXIT_BITMAP_2_FULL
    // unused: VMCS_EOI_EXIT_BITMAP_3_FULL
    // unused: VMCS_EPTP_LIST_ADDRESS_FULL
    // unused: VMCS_VMREAD_BITMAP_ADDRESS_FULL
    // unused: VMCS_VMWRITE_BITMAP_ADDRESS_FULL
    // unused: VMCS_VIRTUALIZATION_EXCEPTION_INFORMATION_ADDRESS_FULL
    // unused: VMCS_XSS_EXITING_BITMAP_FULL
}

void
vmcs_intel_x64::write_32bit_control_state(const vmcs_state_intel_x64 &state)
{
    (void) state;

    uint64_t lower;
    uint64_t upper;

    auto ia32_vmx_pinbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_PINBASED_CTLS_MSR);
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR);
    auto ia32_vmx_exit_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_EXIT_CTLS_MSR);
    auto ia32_vmx_entry_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_ENTRY_CTLS_MSR);

    lower = ((ia32_vmx_pinbased_ctls_msr >> 0) & 0x00000000FFFFFFFF);
    upper = ((ia32_vmx_pinbased_ctls_msr >> 32) & 0x00000000FFFFFFFF);
    vmwrite(VMCS_PIN_BASED_VM_EXECUTION_CONTROLS, lower & upper);

    lower = ((ia32_vmx_procbased_ctls_msr >> 0) & 0x00000000FFFFFFFF);
    upper = ((ia32_vmx_procbased_ctls_msr >> 32) & 0x00000000FFFFFFFF);
    vmwrite(VMCS_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, lower & upper);

    lower = ((ia32_vmx_exit_ctls_msr >> 0) & 0x00000000FFFFFFFF);
    upper = ((ia32_vmx_exit_ctls_msr >> 32) & 0x00000000FFFFFFFF);
    vmwrite(VMCS_VM_EXIT_CONTROLS, lower & upper);

    lower = ((ia32_vmx_entry_ctls_msr >> 0) & 0x00000000FFFFFFFF);
    upper = ((ia32_vmx_entry_ctls_msr >> 32) & 0x00000000FFFFFFFF);
    vmwrite(VMCS_VM_ENTRY_CONTROLS, lower & upper);

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
vmcs_intel_x64::write_natural_control_state(const vmcs_state_intel_x64 &state)
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
vmcs_intel_x64::write_16bit_guest_state(const vmcs_state_intel_x64 &state)
{
    vmwrite(VMCS_GUEST_ES_SELECTOR, state.es());
    vmwrite(VMCS_GUEST_CS_SELECTOR, state.cs());
    vmwrite(VMCS_GUEST_SS_SELECTOR, state.ss());
    vmwrite(VMCS_GUEST_DS_SELECTOR, state.ds());
    vmwrite(VMCS_GUEST_FS_SELECTOR, state.fs());
    vmwrite(VMCS_GUEST_GS_SELECTOR, state.gs());
    vmwrite(VMCS_GUEST_TR_SELECTOR, state.tr());

    // unused: VMCS_GUEST_LDTR_SELECTOR
    // unused: VMCS_GUEST_INTERRUPT_STATUS
}

void
vmcs_intel_x64::write_64bit_guest_state(const vmcs_state_intel_x64 &state)
{
    vmwrite(VMCS_VMCS_LINK_POINTER_FULL, 0xFFFFFFFFFFFFFFFF);
    vmwrite(VMCS_GUEST_IA32_EFER_FULL, state.ia32_efer_msr());

    // unused: VMCS_GUEST_IA32_DEBUGCTL_FULL
    // unused: VMCS_GUEST_IA32_PAT_FULL
    // unused: VMCS_GUEST_IA32_PERF_GLOBAL_CTRL_FULL
    // unused: VMCS_GUEST_PDPTE0_FULL
    // unused: VMCS_GUEST_PDPTE1_FULL
    // unused: VMCS_GUEST_PDPTE2_FULL
    // unused: VMCS_GUEST_PDPTE3_FULL
}

void
vmcs_intel_x64::write_32bit_guest_state(const vmcs_state_intel_x64 &state)
{
    auto unusable = m_intrinsics->segment_descriptor_access(0);

    vmwrite(VMCS_GUEST_ES_LIMIT, state.es_limit());
    vmwrite(VMCS_GUEST_CS_LIMIT, state.cs_limit());
    vmwrite(VMCS_GUEST_SS_LIMIT, state.ss_limit());
    vmwrite(VMCS_GUEST_DS_LIMIT, state.ds_limit());
    vmwrite(VMCS_GUEST_FS_LIMIT, state.fs_limit());
    vmwrite(VMCS_GUEST_GS_LIMIT, state.gs_limit());
    vmwrite(VMCS_GUEST_TR_LIMIT, state.tr_limit());

    vmwrite(VMCS_GUEST_GDTR_LIMIT, state.gdt().limit);
    vmwrite(VMCS_GUEST_IDTR_LIMIT, state.idt().limit);

    vmwrite(VMCS_GUEST_ES_ACCESS_RIGHTS, state.es_access());
    vmwrite(VMCS_GUEST_CS_ACCESS_RIGHTS, state.cs_access());
    vmwrite(VMCS_GUEST_SS_ACCESS_RIGHTS, state.ss_access());
    vmwrite(VMCS_GUEST_DS_ACCESS_RIGHTS, state.ds_access());
    vmwrite(VMCS_GUEST_FS_ACCESS_RIGHTS, state.fs_access());
    vmwrite(VMCS_GUEST_GS_ACCESS_RIGHTS, state.gs_access());
    vmwrite(VMCS_GUEST_LDTR_ACCESS_RIGHTS, unusable);
    vmwrite(VMCS_GUEST_TR_ACCESS_RIGHTS, state.tr_access());

    vmwrite(VMCS_GUEST_IA32_SYSENTER_CS, state.ia32_sysenter_cs_msr());

    // unused: VMCS_GUEST_LDTR_LIMIT
    // unused: VMCS_GUEST_INTERRUPTIBILITY_STATE
    // unused: VMCS_GUEST_ACTIVITY_STATE
    // unused: VMCS_GUEST_SMBASE
    // unused: VMCS_VMX_PREEMPTION_TIMER_VALUE
}

void
vmcs_intel_x64::write_natural_guest_state(const vmcs_state_intel_x64 &state)
{
    vmwrite(VMCS_GUEST_CR0, state.cr0());
    vmwrite(VMCS_GUEST_CR3, state.cr3());
    vmwrite(VMCS_GUEST_CR4, state.cr4());
    vmwrite(VMCS_GUEST_ES_BASE, state.es_base());
    vmwrite(VMCS_GUEST_CS_BASE, state.cs_base());
    vmwrite(VMCS_GUEST_SS_BASE, state.ss_base());
    vmwrite(VMCS_GUEST_DS_BASE, state.ds_base());
    vmwrite(VMCS_GUEST_FS_BASE, state.ia32_fs_base_msr());
    vmwrite(VMCS_GUEST_GS_BASE, state.ia32_gs_base_msr());
    vmwrite(VMCS_GUEST_TR_BASE, state.tr_base());

    vmwrite(VMCS_GUEST_GDTR_BASE, state.gdt().base);
    vmwrite(VMCS_GUEST_IDTR_BASE, state.idt().base);

    vmwrite(VMCS_GUEST_RFLAGS, state.rflags());

    vmwrite(VMCS_GUEST_IA32_SYSENTER_ESP, state.ia32_sysenter_esp_msr());
    vmwrite(VMCS_GUEST_IA32_SYSENTER_EIP, state.ia32_sysenter_eip_msr());

    // unused: VMCS_GUEST_LDTR_BASE
    // unused: VMCS_GUEST_DR7
    // unused: VMCS_GUEST_RSP, see m_intrinsics->vmlaunch()
    // unused: VMCS_GUEST_RIP, see m_intrinsics->vmlaunch()
    // unused: VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS
}

void
vmcs_intel_x64::write_16bit_host_state(const vmcs_state_intel_x64 &state)
{
    vmwrite(VMCS_HOST_CS_SELECTOR, state.cs());
    vmwrite(VMCS_HOST_SS_SELECTOR, state.ss());
    vmwrite(VMCS_HOST_TR_SELECTOR, state.tr());

    // unused: VMCS_HOST_ES_SELECTOR
    // unused: VMCS_HOST_DS_SELECTOR
    // unused: VMCS_HOST_FS_SELECTOR
    // unused: VMCS_HOST_GS_SELECTOR
}

void
vmcs_intel_x64::write_64bit_host_state(const vmcs_state_intel_x64 &state)
{
    (void) state;

    // unused: VMCS_HOST_IA32_PAT_FULL
    // unused: VMCS_HOST_IA32_EFER_FULL
    // unused: VMCS_HOST_IA32_PERF_GLOBAL_CTRL_FULL
}

void
vmcs_intel_x64::write_32bit_host_state(const vmcs_state_intel_x64 &state)
{
    (void) state;

    // unused: VMCS_HOST_IA32_SYSENTER_CS
}

void
vmcs_intel_x64::write_natural_host_state(const vmcs_state_intel_x64 &state)
{
    auto exit_handler_stack = m_exit_handler_stack.get() + STACK_SIZE - 1;

    vmwrite(VMCS_HOST_CR0, state.cr0());
    vmwrite(VMCS_HOST_CR3, state.cr3());
    vmwrite(VMCS_HOST_CR4, state.cr4());

    vmwrite(VMCS_HOST_TR_BASE, state.tr_base());

    vmwrite(VMCS_HOST_GDTR_BASE, state.gdt().base);
    vmwrite(VMCS_HOST_IDTR_BASE, state.idt().base);

    vmwrite(VMCS_HOST_RSP, (uint64_t)exit_handler_stack);
    vmwrite(VMCS_HOST_RIP, (uint64_t)exit_handler_entry);

    // unused: VMCS_HOST_FS_BASE
    // unused: VMCS_HOST_GS_BASE
    // unused: VMCS_HOST_IA32_SYSENTER_ESP
    // unused: VMCS_HOST_IA32_SYSENTER_EIP
}

void
vmcs_intel_x64::promote_16bit_guest_state()
{
    m_intrinsics->write_es(vmread(VMCS_GUEST_ES_SELECTOR));
    // m_intrinsics->write_cs(vmread(VMCS_GUEST_CS_SELECTOR));
    // m_intrinsics->write_ss(vmread(VMCS_GUEST_SS_SELECTOR));
    m_intrinsics->write_ds(vmread(VMCS_GUEST_DS_SELECTOR));
    m_intrinsics->write_fs(vmread(VMCS_GUEST_FS_SELECTOR));
    m_intrinsics->write_gs(vmread(VMCS_GUEST_GS_SELECTOR));
    // m_intrinsics->write_tr(vmread(VMCS_GUEST_TR_SELECTOR));
}

void
vmcs_intel_x64::promote_64bit_guest_state()
{
    auto ia32_efer_msr = vmread(VMCS_GUEST_IA32_EFER_FULL);
    auto ia32_pat_msr = vmread(VMCS_GUEST_IA32_PAT_FULL);

    m_intrinsics->write_msr(IA32_EFER_MSR, ia32_efer_msr);
    m_intrinsics->write_msr(IA32_PAT_MSR, ia32_pat_msr);

    // unused: VMCS_GUEST_IA32_PERF_GLOBAL_CTRL_FULL
}

void
vmcs_intel_x64::promote_32bit_guest_state()
{
    auto ia32_sysenter_cs_msr = vmread(VMCS_GUEST_IA32_SYSENTER_CS);
    m_intrinsics->write_msr(IA32_SYSENTER_CS_MSR, ia32_sysenter_cs_msr);
}

void
vmcs_intel_x64::promote_natural_guest_state()
{
    m_intrinsics->write_cr0(vmread(VMCS_GUEST_CR0));
    m_intrinsics->write_cr3(vmread(VMCS_GUEST_CR3));
    m_intrinsics->write_cr4(vmread(VMCS_GUEST_CR4));

    auto ia32_fs_base_msr = vmread(VMCS_GUEST_FS_BASE);
    auto ia32_gs_base_msr = vmread(VMCS_GUEST_GS_BASE);
    auto ia32_sysenter_esp_msr = vmread(VMCS_GUEST_IA32_SYSENTER_ESP);
    auto ia32_sysenter_eip_msr = vmread(VMCS_GUEST_IA32_SYSENTER_EIP);

    m_intrinsics->write_msr(IA32_FS_BASE_MSR, ia32_fs_base_msr);
    m_intrinsics->write_msr(IA32_GS_BASE_MSR, ia32_gs_base_msr);
    m_intrinsics->write_msr(IA32_SYSENTER_ESP_MSR, ia32_sysenter_esp_msr);
    m_intrinsics->write_msr(IA32_SYSENTER_EIP_MSR, ia32_sysenter_eip_msr);
}

void
vmcs_intel_x64::default_pin_based_vm_execution_controls()
{
    auto controls = vmread(VMCS_PIN_BASED_VM_EXECUTION_CONTROLS);

    // controls |= VM_EXEC_PIN_BASED_EXTERNAL_INTERRUPT_EXITING;
    // controls |= VM_EXEC_PIN_BASED_NMI_EXITING;
    // controls |= VM_EXEC_PIN_BASED_VIRTUAL_NMIS;
    // controls |= VM_EXEC_PIN_BASED_ACTIVATE_VMX_PREEMPTION_TIMER;
    // controls |= VM_EXEC_PIN_BASED_PROCESS_POSTED_INTERRUPTS;

    vmwrite(VMCS_PIN_BASED_VM_EXECUTION_CONTROLS, controls);
}

void
vmcs_intel_x64::default_primary_processor_based_vm_execution_controls()
{
    auto controls = vmread(VMCS_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);

    // controls |= VM_EXEC_P_PROC_BASED_INTERRUPT_WINDOW_EXITING;
    // controls |= VM_EXEC_P_PROC_BASED_USE_TSC_OFFSETTING;
    // controls |= VM_EXEC_P_PROC_BASED_HLT_EXITING;
    // controls |= VM_EXEC_P_PROC_BASED_INVLPG_EXITING;
    // controls |= VM_EXEC_P_PROC_BASED_MWAIT_EXITING;
    // controls |= VM_EXEC_P_PROC_BASED_RDPMC_EXITING;
    // controls |= VM_EXEC_P_PROC_BASED_RDTSC_EXITING;
    // controls |= VM_EXEC_P_PROC_BASED_CR3_LOAD_EXITING;
    // controls |= VM_EXEC_P_PROC_BASED_CR3_STORE_EXITING;
    // controls |= VM_EXEC_P_PROC_BASED_CR8_LOAD_EXITING;
    // controls |= VM_EXEC_P_PROC_BASED_CR8_STORE_EXITING;
    // controls |= VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW;
    // controls |= VM_EXEC_P_PROC_BASED_NMI_WINDOW_EXITING;
    // controls |= VM_EXEC_P_PROC_BASED_MOV_DR_EXITING;
    // controls |= VM_EXEC_P_PROC_BASED_UNCONDITIONAL_IO_EXITING;
    // controls |= VM_EXEC_P_PROC_BASED_USE_IO_BITMAPS;
    // controls |= VM_EXEC_P_PROC_BASED_MONITOR_TRAP_FLAG;
    controls |= VM_EXEC_P_PROC_BASED_USE_MSR_BITMAPS;
    // controls |= VM_EXEC_P_PROC_BASED_MONITOR_EXITING;
    // controls |= VM_EXEC_P_PROC_BASED_PAUSE_EXITING;
    // controls |= VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;

    vmwrite(VMCS_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, controls);
}

void
vmcs_intel_x64::default_secondary_processor_based_vm_execution_controls()
{
    auto controls = vmread(VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);

    // controls |= VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES;
    // controls |= VM_EXEC_S_PROC_BASED_ENABLE_EPT;
    // controls |= VM_EXEC_S_PROC_BASED_DESCRIPTOR_TABLE_EXITING;
    // controls |= VM_EXEC_S_PROC_BASED_ENABLE_RDTSCP;
    // controls |= VM_EXEC_S_PROC_BASED_VIRTUALIZE_X2APIC_MODE;
    // controls |= VM_EXEC_S_PROC_BASED_ENABLE_VPID;
    // controls |= VM_EXEC_S_PROC_BASED_WBINVD_EXITING;
    // controls |= VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST;
    // controls |= VM_EXEC_S_PROC_BASED_APIC_REGISTER_VIRTUALIZATION;
    // controls |= VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY;
    // controls |= VM_EXEC_S_PROC_BASED_PAUSE_LOOP_EXITING;
    // controls |= VM_EXEC_S_PROC_BASED_RDRAND_EXITING;
    // controls |= VM_EXEC_S_PROC_BASED_ENABLE_INVPCID;
    // controls |= VM_EXEC_S_PROC_BASED_ENABLE_VM_FUNCTIONS;
    // controls |= VM_EXEC_S_PROC_BASED_VMCS_SHADOWING;
    // controls |= VM_EXEC_S_PROC_BASED_RDSEED_EXITING;
    // controls |= VM_EXEC_S_PROC_BASED_EPT_VIOLATION_VE;
    // controls |= VM_EXEC_S_PROC_BASED_ENABLE_XSAVES_XRSTORS;

    vmwrite(VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, controls);
}

void
vmcs_intel_x64::default_vm_exit_controls()
{
    auto controls = vmread(VMCS_VM_EXIT_CONTROLS);

    // controls |= VM_EXIT_CONTROL_SAVE_DEBUG_CONTROLS;
    controls |= VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE;
    // controls |= VM_EXIT_CONTROL_LOAD_IA32_PERF_GLOBAL_CTRL;
    // controls |= VM_EXIT_CONTROL_ACKNOWLEDGE_INTERRUPT_ON_EXIT;
    // controls |= VM_EXIT_CONTROL_SAVE_IA32_PAT;
    // controls |= VM_EXIT_CONTROL_LOAD_IA32_PAT;
    // controls |= VM_EXIT_CONTROL_SAVE_IA32_EFER;
    // controls |= VM_EXIT_CONTROL_LOAD_IA32_EFER;
    // controls |= VM_EXIT_CONTROL_SAVE_VMX_PREEMPTION_TIMER_VALUE;

    vmwrite(VMCS_VM_EXIT_CONTROLS, controls);
}

void
vmcs_intel_x64::default_vm_entry_controls()
{
    auto controls = vmread(VMCS_VM_ENTRY_CONTROLS);

    // controls |= VM_ENTRY_CONTROL_LOAD_DEBUG_CONTROLS;
    controls |= VM_ENTRY_CONTROL_IA_32E_MODE_GUEST;
    // controls |= VM_ENTRY_CONTROL_ENTRY_TO_SMM;
    // controls |= VM_ENTRY_CONTROL_DEACTIVATE_DUAL_MONITOR_TREATMENT;
    // controls |= VM_ENTRY_CONTROL_LOAD_IA32_PERF_GLOBAL_CTRL;
    // controls |= VM_ENTRY_CONTROL_LOAD_IA32_PAT;
    // controls |= VM_ENTRY_CONTROL_LOAD_IA32_EFER;

    vmwrite(VMCS_VM_ENTRY_CONTROLS, controls);
}

uint64_t
vmcs_intel_x64::vmread(uint64_t field) const
{
    uint64_t value = 0;

    if (m_intrinsics->vmread(field, &value) == false)
        throw vmcs_read_failure(field);

    return value;
}

void
vmcs_intel_x64::vmwrite(uint64_t field, uint64_t value)
{
    if (m_intrinsics->vmwrite(field, value) == false)
        throw vmcs_write_failure(field, value);
}
