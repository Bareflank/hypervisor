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
#include <view_as_pointer.h>
#include <vmcs/vmcs_intel_x64.h>

#if 0

void
vmcs_intel_x64::dump_vmcs()
{
    bfdebug << "----------------------------------------" << bfendl;
    bfdebug << "- VMCS Dump                            -" << bfendl;
    bfdebug << "----------------------------------------" << bfendl;

    this->dump_vmcs_16bit_control_state();
    this->dump_vmcs_16bit_guest_state();
    this->dump_vmcs_16bit_host_state();
    this->dump_vmcs_64bit_control_state();
    this->dump_vmcs_64bit_readonly_state();
    this->dump_vmcs_64bit_guest_state();
    this->dump_vmcs_64bit_host_state();
    this->dump_vmcs_32bit_control_state();
    this->dump_vmcs_32bit_readonly_state();
    this->dump_vmcs_32bit_guest_state();
    this->dump_vmcs_32bit_host_state();
    this->dump_vmcs_natural_control_state();
    this->dump_vmcs_natural_readonly_state();
    this->dump_vmcs_natural_guest_state();
    this->dump_vmcs_natural_host_state();

    bfdebug << bfendl;
}

void
vmcs_intel_x64::dump_vmcs_16bit_control_state()
{
    bfdebug << bfendl;
    bfdebug << "16bit Control Fields:" << bfendl;
    PRINT_FIELD(is_supported_vpid(),
                VMCS_VIRTUAL_PROCESSOR_IDENTIFIER);
    PRINT_FIELD(is_supported_posted_interrupts(),
                VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR);
    PRINT_FIELD(is_supported_ept_violation_ve(),
                VMCS_EPTP_INDEX);
}

void
vmcs_intel_x64::dump_vmcs_16bit_guest_state()
{
    bfdebug << bfendl;
    bfdebug << "16bit Guest State Fields:" << bfendl;
    PRINT_FIELD(true, VMCS_GUEST_ES_SELECTOR);
    PRINT_FIELD(true, VMCS_GUEST_CS_SELECTOR);
    PRINT_FIELD(true, VMCS_GUEST_SS_SELECTOR);
    PRINT_FIELD(true, VMCS_GUEST_DS_SELECTOR);
    PRINT_FIELD(true, VMCS_GUEST_FS_SELECTOR);
    PRINT_FIELD(true, VMCS_GUEST_GS_SELECTOR);
    PRINT_FIELD(true, VMCS_GUEST_LDTR_SELECTOR);
    PRINT_FIELD(true, VMCS_GUEST_TR_SELECTOR);
    PRINT_FIELD(is_supported_virtual_interrupt_delivery(),
                VMCS_GUEST_INTERRUPT_STATUS);
}

void
vmcs_intel_x64::dump_vmcs_16bit_host_state()
{
    bfdebug << bfendl;
    bfdebug << "16bit Host State Fields:" << bfendl;
    PRINT_FIELD(true, VMCS_HOST_ES_SELECTOR);
    PRINT_FIELD(true, VMCS_HOST_CS_SELECTOR);
    PRINT_FIELD(true, VMCS_HOST_SS_SELECTOR);
    PRINT_FIELD(true, VMCS_HOST_DS_SELECTOR);
    PRINT_FIELD(true, VMCS_HOST_FS_SELECTOR);
    PRINT_FIELD(true, VMCS_HOST_GS_SELECTOR);
    PRINT_FIELD(true, VMCS_HOST_TR_SELECTOR);
}

void
vmcs_intel_x64::dump_vmcs_64bit_control_state()
{
    bfdebug << bfendl;
    bfdebug << "64bit Control Fields:" << bfendl;
    PRINT_FIELD(true, VMCS_ADDRESS_OF_IO_BITMAP_A_FULL);
    PRINT_FIELD(true, VMCS_ADDRESS_OF_IO_BITMAP_A_HIGH);
    PRINT_FIELD(true, VMCS_ADDRESS_OF_IO_BITMAP_B_FULL);
    PRINT_FIELD(true, VMCS_ADDRESS_OF_IO_BITMAP_B_HIGH);
    PRINT_FIELD(is_supported_msr_bitmaps(),
                VMCS_ADDRESS_OF_MSR_BITMAPS_FULL);
    PRINT_FIELD(is_supported_msr_bitmaps(),
                VMCS_ADDRESS_OF_MSR_BITMAPS_HIGH);
    PRINT_FIELD(true, VMCS_VM_EXIT_MSR_STORE_ADDRESS_FULL);
    PRINT_FIELD(true, VMCS_VM_EXIT_MSR_STORE_ADDRESS_HIGH);
    PRINT_FIELD(true, VMCS_VM_EXIT_MSR_LOAD_ADDRESS_FULL);
    PRINT_FIELD(true, VMCS_VM_EXIT_MSR_LOAD_ADDRESS_HIGH);
    PRINT_FIELD(true, VMCS_VM_ENTRY_MSR_LOAD_ADDRESS_FULL);
    PRINT_FIELD(true, VMCS_VM_ENTRY_MSR_LOAD_ADDRESS_HIGH);
    PRINT_FIELD(true, VMCS_EXECUTIVE_VMCS_POINTER_FULL);
    PRINT_FIELD(true, VMCS_EXECUTIVE_VMCS_POINTER_HIGH);
    PRINT_FIELD(true, VMCS_TSC_OFFSET_FULL);
    PRINT_FIELD(true, VMCS_TSC_OFFSET_HIGH);
    PRINT_FIELD(is_supported_tpr_shadow(),
                VMCS_VIRTUAL_APIC_ADDRESS_FULL);
    PRINT_FIELD(is_supported_tpr_shadow(),
                VMCS_VIRTUAL_APIC_ADDRESS_HIGH);
    PRINT_FIELD(is_supported_virtualized_apic(),
                VMCS_APIC_ACCESS_ADDRESS_FULL);
    PRINT_FIELD(is_supported_virtualized_apic(),
                VMCS_APIC_ACCESS_ADDRESS_HIGH);
    PRINT_FIELD(is_supported_posted_interrupts(),
                VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_FULL);
    PRINT_FIELD(is_supported_posted_interrupts(),
                VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_HIGH);
    PRINT_FIELD(is_supported_vm_functions(),
                VMCS_VM_FUNCTION_CONTROLS_FULL);
    PRINT_FIELD(is_supported_vm_functions(),
                VMCS_VM_FUNCTION_CONTROLS_HIGH);
    PRINT_FIELD(is_supported_ept(),
                VMCS_EPT_POINTER_FULL);
    PRINT_FIELD(is_supported_ept(),
                VMCS_EPT_POINTER_HIGH);
    PRINT_FIELD(is_supported_virtual_interrupt_delivery(),
                VMCS_EOI_EXIT_BITMAP_0_FULL);
    PRINT_FIELD(is_supported_virtual_interrupt_delivery(),
                VMCS_EOI_EXIT_BITMAP_0_HIGH);
    PRINT_FIELD(is_supported_virtual_interrupt_delivery(),
                VMCS_EOI_EXIT_BITMAP_1_FULL);
    PRINT_FIELD(is_supported_virtual_interrupt_delivery(),
                VMCS_EOI_EXIT_BITMAP_1_HIGH);
    PRINT_FIELD(is_supported_virtual_interrupt_delivery(),
                VMCS_EOI_EXIT_BITMAP_2_FULL);
    PRINT_FIELD(is_supported_virtual_interrupt_delivery(),
                VMCS_EOI_EXIT_BITMAP_2_HIGH);
    PRINT_FIELD(is_supported_virtual_interrupt_delivery(),
                VMCS_EOI_EXIT_BITMAP_3_FULL);
    PRINT_FIELD(is_supported_virtual_interrupt_delivery(),
                VMCS_EOI_EXIT_BITMAP_3_HIGH);
    PRINT_FIELD(is_supported_eptp_switching(),
                VMCS_EPTP_LIST_ADDRESS_FULL);
    PRINT_FIELD(is_supported_eptp_switching(),
                VMCS_EPTP_LIST_ADDRESS_HIGH);
    PRINT_FIELD(is_supported_vmcs_shadowing(),
                VMCS_VMREAD_BITMAP_ADDRESS_FULL);
    PRINT_FIELD(is_supported_vmcs_shadowing(),
                VMCS_VMREAD_BITMAP_ADDRESS_HIGH);
    PRINT_FIELD(is_supported_vmcs_shadowing(),
                VMCS_VMWRITE_BITMAP_ADDRESS_FULL);
    PRINT_FIELD(is_supported_vmcs_shadowing(),
                VMCS_VMWRITE_BITMAP_ADDRESS_HIGH);
    PRINT_FIELD(is_supported_ept_violation_ve(),
                VMCS_VIRTUALIZATION_EXCEPTION_INFORMATION_ADDRESS_FULL);
    PRINT_FIELD(is_supported_ept_violation_ve(),
                VMCS_VIRTUALIZATION_EXCEPTION_INFORMATION_ADDRESS_HIGH);
    PRINT_FIELD(is_supported_xsave_xrestore(),
                VMCS_XSS_EXITING_BITMAP_FULL);
    PRINT_FIELD(is_supported_xsave_xrestore(),
                VMCS_XSS_EXITING_BITMAP_HIGH);
}

void
vmcs_intel_x64::dump_vmcs_64bit_readonly_state()
{
    bfdebug << bfendl;
    bfdebug << "64bit Read-Only Data Fields:" << bfendl;
    PRINT_FIELD(is_supported_ept(),
                VMCS_GUEST_PHYSICAL_ADDRESS_FULL);
    PRINT_FIELD(is_supported_ept(),
                VMCS_GUEST_PHYSICAL_ADDRESS_HIGH);
}

void
vmcs_intel_x64::dump_vmcs_64bit_guest_state()
{
    bfdebug << bfendl;
    bfdebug << "64bit Guest State Fields:" << bfendl;
    PRINT_FIELD(true, VMCS_VMCS_LINK_POINTER_FULL);
    PRINT_FIELD(true, VMCS_VMCS_LINK_POINTER_HIGH);
    PRINT_FIELD(true, VMCS_GUEST_IA32_DEBUGCTL_FULL);
    PRINT_FIELD(true, VMCS_GUEST_IA32_DEBUGCTL_HIGH);
    PRINT_FIELD(is_supported_load_ia32_pat_on_entry(),
                VMCS_GUEST_IA32_PAT_FULL);
    PRINT_FIELD(is_supported_load_ia32_pat_on_entry(),
                VMCS_GUEST_IA32_PAT_HIGH);
    PRINT_FIELD(is_supported_load_ia32_efer_on_entry(),
                VMCS_GUEST_IA32_EFER_FULL);
    PRINT_FIELD(is_supported_load_ia32_efer_on_entry(),
                VMCS_GUEST_IA32_EFER_HIGH);
    PRINT_FIELD(is_supported_load_ia32_perf_global_ctrl_on_entry(),
                VMCS_GUEST_IA32_PERF_GLOBAL_CTRL_FULL);
    PRINT_FIELD(is_supported_load_ia32_perf_global_ctrl_on_entry(),
                VMCS_GUEST_IA32_PERF_GLOBAL_CTRL_HIGH);
    PRINT_FIELD(is_supported_ept(),
                VMCS_GUEST_PDPTE0_FULL);
    PRINT_FIELD(is_supported_ept(),
                VMCS_GUEST_PDPTE0_HIGH);
    PRINT_FIELD(is_supported_ept(),
                VMCS_GUEST_PDPTE1_FULL);
    PRINT_FIELD(is_supported_ept(),
                VMCS_GUEST_PDPTE1_HIGH);
    PRINT_FIELD(is_supported_ept(),
                VMCS_GUEST_PDPTE2_FULL);
    PRINT_FIELD(is_supported_ept(),
                VMCS_GUEST_PDPTE2_HIGH);
    PRINT_FIELD(is_supported_ept(),
                VMCS_GUEST_PDPTE3_FULL);
    PRINT_FIELD(is_supported_ept(),
                VMCS_GUEST_PDPTE3_HIGH);
}

void
vmcs_intel_x64::dump_vmcs_64bit_host_state()
{
    bfdebug << bfendl;
    bfdebug << "64bit Host State Fields:" << bfendl;
    PRINT_FIELD(is_supported_load_ia32_pat_on_exit(),
                VMCS_HOST_IA32_PAT_FULL);
    PRINT_FIELD(is_supported_load_ia32_pat_on_exit(),
                VMCS_HOST_IA32_PAT_HIGH);
    PRINT_FIELD(is_supported_load_ia32_efer_on_exit(),
                VMCS_HOST_IA32_EFER_FULL);
    PRINT_FIELD(is_supported_load_ia32_efer_on_exit(),
                VMCS_HOST_IA32_EFER_HIGH);
    PRINT_FIELD(is_supported_load_ia32_perf_global_ctrl_on_exit(),
                VMCS_HOST_IA32_PERF_GLOBAL_CTRL_FULL);
    PRINT_FIELD(is_supported_load_ia32_perf_global_ctrl_on_exit(),
                VMCS_HOST_IA32_PERF_GLOBAL_CTRL_HIGH);
}

void
vmcs_intel_x64::dump_vmcs_32bit_control_state()
{
    bfdebug << bfendl;
    bfdebug << "32bit Control Fields:" << bfendl;
    PRINT_FIELD(true, VMCS_PIN_BASED_VM_EXECUTION_CONTROLS);
    PRINT_FIELD(true, VMCS_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);
    PRINT_FIELD(true, VMCS_EXCEPTION_BITMAP);
    PRINT_FIELD(true, VMCS_PAGE_FAULT_ERROR_CODE_MASK);
    PRINT_FIELD(true, VMCS_PAGE_FAULT_ERROR_CODE_MATCH);
    PRINT_FIELD(true, VMCS_CR3_TARGET_COUNT);
    PRINT_FIELD(true, VMCS_VM_EXIT_CONTROLS);
    PRINT_FIELD(true, VMCS_VM_EXIT_MSR_STORE_COUNT);
    PRINT_FIELD(true, VMCS_VM_EXIT_MSR_LOAD_COUNT);
    PRINT_FIELD(true, VMCS_VM_ENTRY_CONTROLS);
    PRINT_FIELD(true, VMCS_VM_ENTRY_MSR_LOAD_COUNT);
    PRINT_FIELD(true, VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD);
    PRINT_FIELD(true, VMCS_VM_ENTRY_EXCEPTION_ERROR_CODE);
    PRINT_FIELD(true, VMCS_VM_ENTRY_INSTRUCTION_LENGTH);
    PRINT_FIELD(is_supported_tpr_shadow(),
                VMCS_TPR_THRESHOLD);
    PRINT_FIELD(is_supported_secondary_controls(),
                VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);
    PRINT_FIELD(is_supported_pause_loop_exiting(),
                VMCS_PLE_GAP);
    PRINT_FIELD(is_supported_pause_loop_exiting(),
                VMCS_PLE_WINDOW);
}

void
vmcs_intel_x64::dump_vmcs_32bit_readonly_state()
{
    bfdebug << bfendl;
    bfdebug << "32bit Read-Only Fields:" << bfendl;
    PRINT_FIELD(true, VMCS_VM_INSTRUCTION_ERROR);
    PRINT_FIELD(true, VMCS_EXIT_REASON);
    PRINT_FIELD(true, VMCS_VM_EXIT_INTERRUPTION_INFORMATION);
    PRINT_FIELD(true, VMCS_VM_EXIT_INTERRUPTION_ERROR_CODE);
    PRINT_FIELD(true, VMCS_IDT_VECTORING_INFORMATION_FIELD);
    PRINT_FIELD(true, VMCS_IDT_VECTORING_ERROR_CODE);
    PRINT_FIELD(true, VMCS_VM_EXIT_INSTRUCTION_LENGTH);
    PRINT_FIELD(true, VMCS_VM_EXIT_INSTRUCTION_INFORMATION);
}

void
vmcs_intel_x64::dump_vmcs_32bit_guest_state()
{
    bfdebug << bfendl;
    bfdebug << "32bit Guest State Fields:" << bfendl;
    PRINT_FIELD(true, VMCS_GUEST_ES_LIMIT);
    PRINT_FIELD(true, VMCS_GUEST_CS_LIMIT);
    PRINT_FIELD(true, VMCS_GUEST_SS_LIMIT);
    PRINT_FIELD(true, VMCS_GUEST_DS_LIMIT);
    PRINT_FIELD(true, VMCS_GUEST_FS_LIMIT);
    PRINT_FIELD(true, VMCS_GUEST_GS_LIMIT);
    PRINT_FIELD(true, VMCS_GUEST_LDTR_LIMIT);
    PRINT_FIELD(true, VMCS_GUEST_TR_LIMIT);
    PRINT_FIELD(true, VMCS_GUEST_GDTR_LIMIT);
    PRINT_FIELD(true, VMCS_GUEST_IDTR_LIMIT);
    PRINT_FIELD(true, VMCS_GUEST_ES_ACCESS_RIGHTS);
    PRINT_FIELD(true, VMCS_GUEST_CS_ACCESS_RIGHTS);
    PRINT_FIELD(true, VMCS_GUEST_SS_ACCESS_RIGHTS);
    PRINT_FIELD(true, VMCS_GUEST_DS_ACCESS_RIGHTS);
    PRINT_FIELD(true, VMCS_GUEST_FS_ACCESS_RIGHTS);
    PRINT_FIELD(true, VMCS_GUEST_GS_ACCESS_RIGHTS);
    PRINT_FIELD(true, VMCS_GUEST_LDTR_ACCESS_RIGHTS);
    PRINT_FIELD(true, VMCS_GUEST_TR_ACCESS_RIGHTS);
    PRINT_FIELD(true, VMCS_GUEST_INTERRUPTIBILITY_STATE);
    PRINT_FIELD(true, VMCS_GUEST_ACTIVITY_STATE);
    PRINT_FIELD(true, VMCS_GUEST_SMBASE);
    PRINT_FIELD(true, VMCS_GUEST_IA32_SYSENTER_CS);
    PRINT_FIELD(is_supported_vmx_preemption_timer(),
                VMCS_VMX_PREEMPTION_TIMER_VALUE);
}

void
vmcs_intel_x64::dump_vmcs_32bit_host_state()
{
    bfdebug << bfendl;
    bfdebug << "32bit Host State Fields:" << bfendl;
    PRINT_FIELD(true, VMCS_HOST_IA32_SYSENTER_CS);
}

void
vmcs_intel_x64::dump_vmcs_natural_control_state()
{
    bfdebug << bfendl;
    bfdebug << "Natural Width Control Fields:" << bfendl;
    PRINT_FIELD(true, VMCS_CR0_GUEST_HOST_MASK);
    PRINT_FIELD(true, VMCS_CR4_GUEST_HOST_MASK);
    PRINT_FIELD(true, VMCS_CR0_READ_SHADOW);
    PRINT_FIELD(true, VMCS_CR4_READ_SHADOW);
    PRINT_FIELD(true, VMCS_CR3_TARGET_VALUE_0);
    PRINT_FIELD(true, VMCS_CR3_TARGET_VALUE_1);
    PRINT_FIELD(true, VMCS_CR3_TARGET_VALUE_2);
    PRINT_FIELD(true, VMCS_CR3_TARGET_VALUE_31);
}

void
vmcs_intel_x64::dump_vmcs_natural_readonly_state()
{
    bfdebug << bfendl;
    bfdebug << "Natural Width Read-Only Fields:" << bfendl;
    PRINT_FIELD(true, VMCS_EXIT_QUALIFICATION);
    PRINT_FIELD(true, VMCS_IO_RCX);
    PRINT_FIELD(true, VMCS_IO_RSI);
    PRINT_FIELD(true, VMCS_IO_RDI);
    PRINT_FIELD(true, VMCS_IO_RIP);
    PRINT_FIELD(true, VMCS_GUEST_LINEAR_ADDRESS);
}

void
vmcs_intel_x64::dump_vmcs_natural_guest_state()
{
    bfdebug << bfendl;
    bfdebug << "Natural Width Guest State Fields:" << bfendl;
    PRINT_FIELD(true, VMCS_GUEST_CR0);
    PRINT_FIELD(true, VMCS_GUEST_CR3);
    PRINT_FIELD(true, VMCS_GUEST_CR4);
    PRINT_FIELD(true, VMCS_GUEST_ES_BASE);
    PRINT_FIELD(true, VMCS_GUEST_CS_BASE);
    PRINT_FIELD(true, VMCS_GUEST_SS_BASE);
    PRINT_FIELD(true, VMCS_GUEST_DS_BASE);
    PRINT_FIELD(true, VMCS_GUEST_FS_BASE);
    PRINT_FIELD(true, VMCS_GUEST_GS_BASE);
    PRINT_FIELD(true, VMCS_GUEST_LDTR_BASE);
    PRINT_FIELD(true, VMCS_GUEST_TR_BASE);
    PRINT_FIELD(true, VMCS_GUEST_GDTR_BASE);
    PRINT_FIELD(true, VMCS_GUEST_IDTR_BASE);
    PRINT_FIELD(true, VMCS_GUEST_DR7);
    PRINT_FIELD(true, VMCS_GUEST_RSP);
    PRINT_FIELD(true, VMCS_GUEST_RIP);
    PRINT_FIELD(true, VMCS_GUEST_RFLAGS);
    PRINT_FIELD(true, VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS);
    PRINT_FIELD(true, VMCS_GUEST_IA32_SYSENTER_ESP);
    PRINT_FIELD(true, VMCS_GUEST_IA32_SYSENTER_EIP);
}

void
vmcs_intel_x64::dump_vmcs_natural_host_state()
{
    bfdebug << bfendl;
    bfdebug << "Natural Width Host State Fields:" << bfendl;
    PRINT_FIELD(true, VMCS_HOST_CR0);
    PRINT_FIELD(true, VMCS_HOST_CR3);
    PRINT_FIELD(true, VMCS_HOST_CR4);
    PRINT_FIELD(true, VMCS_HOST_FS_BASE);
    PRINT_FIELD(true, VMCS_HOST_GS_BASE);
    PRINT_FIELD(true, VMCS_HOST_TR_BASE);
    PRINT_FIELD(true, VMCS_HOST_GDTR_BASE);
    PRINT_FIELD(true, VMCS_HOST_IDTR_BASE);
    PRINT_FIELD(true, VMCS_HOST_IA32_SYSENTER_ESP);
    PRINT_FIELD(true, VMCS_HOST_IA32_SYSENTER_EIP);
    PRINT_FIELD(true, VMCS_HOST_RSP);
    PRINT_FIELD(true, VMCS_HOST_RIP);
}

void
vmcs_intel_x64::print_execution_controls()
{
    print_pin_based_vm_execution_controls();
    print_primary_processor_based_vm_execution_controls();
    print_secondary_processor_based_vm_execution_controls();
    print_vm_exit_control_fields();
    print_vm_entry_control_fields();
}

void
vmcs_intel_x64::print_pin_based_vm_execution_controls()
{
    auto controls =
        vmread(VMCS_PIN_BASED_VM_EXECUTION_CONTROLS);

    bfdebug << "----------------------------------------" << bfendl;
    bfdebug << "- Pin VM Execution Controls            -" << bfendl;
    bfdebug << "----------------------------------------" << bfendl;

    PRINT_CONTROL(VM_EXEC_PIN_BASED_EXTERNAL_INTERRUPT_EXITING);
    PRINT_CONTROL(VM_EXEC_PIN_BASED_NMI_EXITING);
    PRINT_CONTROL(VM_EXEC_PIN_BASED_VIRTUAL_NMIS);
    PRINT_CONTROL(VM_EXEC_PIN_BASED_ACTIVATE_VMX_PREEMPTION_TIMER);
    PRINT_CONTROL(VM_EXEC_PIN_BASED_PROCESS_POSTED_INTERRUPTS);

    bfdebug << bfendl;
}

void
vmcs_intel_x64::print_primary_processor_based_vm_execution_controls()
{
    auto controls =
        vmread(VMCS_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);

    bfdebug << "----------------------------------------" << bfendl;
    bfdebug << "- Proc VM Execution Controls           -" << bfendl;
    bfdebug << "----------------------------------------" << bfendl;

    PRINT_CONTROL(VM_EXEC_P_PROC_BASED_INTERRUPT_WINDOW_EXITING);
    PRINT_CONTROL(VM_EXEC_P_PROC_BASED_USE_TSC_OFFSETTING);
    PRINT_CONTROL(VM_EXEC_P_PROC_BASED_HLT_EXITING);
    PRINT_CONTROL(VM_EXEC_P_PROC_BASED_INVLPG_EXITING);
    PRINT_CONTROL(VM_EXEC_P_PROC_BASED_MWAIT_EXITING);
    PRINT_CONTROL(VM_EXEC_P_PROC_BASED_RDPMC_EXITING);
    PRINT_CONTROL(VM_EXEC_P_PROC_BASED_RDTSC_EXITING);
    PRINT_CONTROL(VM_EXEC_P_PROC_BASED_CR3_LOAD_EXITING);
    PRINT_CONTROL(VM_EXEC_P_PROC_BASED_CR3_STORE_EXITING);
    PRINT_CONTROL(VM_EXEC_P_PROC_BASED_CR8_LOAD_EXITING);
    PRINT_CONTROL(VM_EXEC_P_PROC_BASED_CR8_STORE_EXITING);
    PRINT_CONTROL(VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW);
    PRINT_CONTROL(VM_EXEC_P_PROC_BASED_NMI_WINDOW_EXITING);
    PRINT_CONTROL(VM_EXEC_P_PROC_BASED_MOV_DR_EXITING);
    PRINT_CONTROL(VM_EXEC_P_PROC_BASED_UNCONDITIONAL_IO_EXITING);
    PRINT_CONTROL(VM_EXEC_P_PROC_BASED_USE_IO_BITMAPS);
    PRINT_CONTROL(VM_EXEC_P_PROC_BASED_MONITOR_TRAP_FLAG);
    PRINT_CONTROL(VM_EXEC_P_PROC_BASED_USE_MSR_BITMAPS);
    PRINT_CONTROL(VM_EXEC_P_PROC_BASED_MONITOR_EXITING);
    PRINT_CONTROL(VM_EXEC_P_PROC_BASED_PAUSE_EXITING);
    PRINT_CONTROL(VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS);

    bfdebug << bfendl;
}

void
vmcs_intel_x64::print_secondary_processor_based_vm_execution_controls()
{
    auto controls =
        vmread(VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);

    bfdebug << "----------------------------------------" << bfendl;
    bfdebug << "- Secondary Proc VM Execution Controls -" << bfendl;
    bfdebug << "----------------------------------------" << bfendl;

    PRINT_CONTROL(VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES);
    PRINT_CONTROL(VM_EXEC_S_PROC_BASED_ENABLE_EPT);
    PRINT_CONTROL(VM_EXEC_S_PROC_BASED_DESCRIPTOR_TABLE_EXITING);
    PRINT_CONTROL(VM_EXEC_S_PROC_BASED_ENABLE_RDTSCP);
    PRINT_CONTROL(VM_EXEC_S_PROC_BASED_VIRTUALIZE_X2APIC_MODE);
    PRINT_CONTROL(VM_EXEC_S_PROC_BASED_ENABLE_VPID);
    PRINT_CONTROL(VM_EXEC_S_PROC_BASED_WBINVD_EXITING);
    PRINT_CONTROL(VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST);
    PRINT_CONTROL(VM_EXEC_S_PROC_BASED_APIC_REGISTER_VIRTUALIZATION);
    PRINT_CONTROL(VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY);
    PRINT_CONTROL(VM_EXEC_S_PROC_BASED_PAUSE_LOOP_EXITING);
    PRINT_CONTROL(VM_EXEC_S_PROC_BASED_RDRAND_EXITING);
    PRINT_CONTROL(VM_EXEC_S_PROC_BASED_ENABLE_INVPCID);
    PRINT_CONTROL(VM_EXEC_S_PROC_BASED_ENABLE_VM_FUNCTIONS);
    PRINT_CONTROL(VM_EXEC_S_PROC_BASED_VMCS_SHADOWING);
    PRINT_CONTROL(VM_EXEC_S_PROC_BASED_RDSEED_EXITING);
    PRINT_CONTROL(VM_EXEC_S_PROC_BASED_EPT_VIOLATION_VE);
    PRINT_CONTROL(VM_EXEC_S_PROC_BASED_ENABLE_XSAVES_XRSTORS);

    bfdebug << bfendl;
}

void
vmcs_intel_x64::print_vm_exit_control_fields()
{
    auto controls =
        vmread(VMCS_VM_EXIT_CONTROLS);

    bfdebug << "----------------------------------------" << bfendl;
    bfdebug << "- VM Exit Controls                     -" << bfendl;
    bfdebug << "----------------------------------------" << bfendl;

    PRINT_CONTROL(VM_EXIT_CONTROL_SAVE_DEBUG_CONTROLS);
    PRINT_CONTROL(VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE);
    PRINT_CONTROL(VM_EXIT_CONTROL_LOAD_IA32_PERF_GLOBAL_CTRL);
    PRINT_CONTROL(VM_EXIT_CONTROL_ACKNOWLEDGE_INTERRUPT_ON_EXIT);
    PRINT_CONTROL(VM_EXIT_CONTROL_SAVE_IA32_PAT);
    PRINT_CONTROL(VM_EXIT_CONTROL_LOAD_IA32_PAT);
    PRINT_CONTROL(VM_EXIT_CONTROL_SAVE_IA32_EFER);
    PRINT_CONTROL(VM_EXIT_CONTROL_LOAD_IA32_EFER);
    PRINT_CONTROL(VM_EXIT_CONTROL_SAVE_VMX_PREEMPTION_TIMER_VALUE);

    bfdebug << bfendl;
}

void
vmcs_intel_x64::print_vm_entry_control_fields()
{
    auto controls =
        vmread(VMCS_VM_ENTRY_CONTROLS);

    bfdebug << "----------------------------------------" << bfendl;
    bfdebug << "- VM Entry Controls                    -" << bfendl;
    bfdebug << "----------------------------------------" << bfendl;

    PRINT_CONTROL(VM_ENTRY_CONTROL_LOAD_DEBUG_CONTROLS);
    PRINT_CONTROL(VM_ENTRY_CONTROL_IA_32E_MODE_GUEST);
    PRINT_CONTROL(VM_ENTRY_CONTROL_ENTRY_TO_SMM);
    PRINT_CONTROL(VM_ENTRY_CONTROL_DEACTIVATE_DUAL_MONITOR_TREATMENT);
    PRINT_CONTROL(VM_ENTRY_CONTROL_LOAD_IA32_PERF_GLOBAL_CTRL);
    PRINT_CONTROL(VM_ENTRY_CONTROL_LOAD_IA32_PAT);
    PRINT_CONTROL(VM_ENTRY_CONTROL_LOAD_IA32_EFER);

    bfdebug << bfendl;
}

#endif
