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

#include <iomanip>
#include <iostream>

#include <vmcs/vmcs_intel_x64.h>

#define PRINT_FIELD(a) \
    std::cout << std::left << std::setw(55) << #a \
              << "0x" << vmread(a) << std::endl;

void
vmcs_intel_x64::dump_vmcs()
{
    std::cout << std::hex << std::endl;
    std::cout << "VMCS Dump:" << std::endl;
    std::cout << "----------------------------------------------------------------------" << std::endl;

    // If you read from a VMCS field that is not supported by your processor,
    // you will end up with an error in the VMCS_VM_INSTRUCTION_ERROR field
    // (likely 0xC). The fields commented below are not supported by default
    // but can be used if your hardware supports them.

    std::cout << std::endl;
    std::cout << "16bit Control Fields:" << std::endl;
    PRINT_FIELD(VMCS_VIRTUAL_PROCESSOR_IDENTIFIER);
    // PRINT_FIELD(VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR);
    // PRINT_FIELD(VMCS_EPTP_INDEX);

    std::cout << std::endl;
    std::cout << "16bit Guest State Fields:" << std::endl;
    PRINT_FIELD(VMCS_GUEST_ES_SELECTOR);
    PRINT_FIELD(VMCS_GUEST_CS_SELECTOR);
    PRINT_FIELD(VMCS_GUEST_SS_SELECTOR);
    PRINT_FIELD(VMCS_GUEST_DS_SELECTOR);
    PRINT_FIELD(VMCS_GUEST_FS_SELECTOR);
    PRINT_FIELD(VMCS_GUEST_GS_SELECTOR);
    PRINT_FIELD(VMCS_GUEST_LDTR_SELECTOR);
    PRINT_FIELD(VMCS_GUEST_TR_SELECTOR);
    // PRINT_FIELD(VMCS_GUEST_INTERRUPT_STATUS);

    std::cout << std::endl;
    std::cout << "16bit Host State Fields:" << std::endl;
    PRINT_FIELD(VMCS_HOST_ES_SELECTOR);
    PRINT_FIELD(VMCS_HOST_CS_SELECTOR);
    PRINT_FIELD(VMCS_HOST_SS_SELECTOR);
    PRINT_FIELD(VMCS_HOST_DS_SELECTOR);
    PRINT_FIELD(VMCS_HOST_FS_SELECTOR);
    PRINT_FIELD(VMCS_HOST_GS_SELECTOR);
    PRINT_FIELD(VMCS_HOST_TR_SELECTOR);

    std::cout << std::endl;
    std::cout << "64bit Control Fields:" << std::endl;
    PRINT_FIELD(VMCS_ADDRESS_OF_IO_BITMAP_A_FULL);
    PRINT_FIELD(VMCS_ADDRESS_OF_IO_BITMAP_A_HIGH);
    PRINT_FIELD(VMCS_ADDRESS_OF_IO_BITMAP_B_FULL);
    PRINT_FIELD(VMCS_ADDRESS_OF_IO_BITMAP_B_HIGH);
    PRINT_FIELD(VMCS_ADDRESS_OF_MSR_BITMAPS_FULL);
    PRINT_FIELD(VMCS_ADDRESS_OF_MSR_BITMAPS_HIGH);
    PRINT_FIELD(VMCS_VM_EXIT_MSR_STORE_ADDRESS_FULL);
    PRINT_FIELD(VMCS_VM_EXIT_MSR_STORE_ADDRESS_HIGH);
    PRINT_FIELD(VMCS_VM_EXIT_MSR_LOAD_ADDRESS_FULL);
    PRINT_FIELD(VMCS_VM_EXIT_MSR_LOAD_ADDRESS_HIGH);
    PRINT_FIELD(VMCS_VM_ENTRY_MSR_LOAD_ADDRESS_FULL);
    PRINT_FIELD(VMCS_VM_ENTRY_MSR_LOAD_ADDRESS_HIGH);
    PRINT_FIELD(VMCS_EXECUTIVE_VMCS_POINTER_FULL);
    PRINT_FIELD(VMCS_EXECUTIVE_VMCS_POINTER_HIGH);
    PRINT_FIELD(VMCS_TSC_OFFSET_FULL);
    PRINT_FIELD(VMCS_TSC_OFFSET_HIGH);
    // PRINT_FIELD(VMCS_VIRTUAL_APIC_ADDRESS_FULL);
    // PRINT_FIELD(VMCS_VIRTUAL_APIC_ADDRESS_HIGH);
    // PRINT_FIELD(VMCS_APIC_ACCESS_ADDRESS_FULL);
    // PRINT_FIELD(VMCS_APIC_ACCESS_ADDRESS_HIGH);
    // PRINT_FIELD(VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_FULL);
    // PRINT_FIELD(VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_HIGH);
    PRINT_FIELD(VMCS_VM_FUNCTION_CONTROLS_FULL);
    PRINT_FIELD(VMCS_VM_FUNCTION_CONTROLS_HIGH);
    PRINT_FIELD(VMCS_EPT_POINTER_FULL);
    PRINT_FIELD(VMCS_EPT_POINTER_HIGH);
    // PRINT_FIELD(VMCS_EOI_EXIT_BITMAP_0_FULL);
    // PRINT_FIELD(VMCS_EOI_EXIT_BITMAP_0_HIGH);
    // PRINT_FIELD(VMCS_EOI_EXIT_BITMAP_1_FULL);
    // PRINT_FIELD(VMCS_EOI_EXIT_BITMAP_1_HIGH);
    // PRINT_FIELD(VMCS_EOI_EXIT_BITMAP_2_FULL);
    // PRINT_FIELD(VMCS_EOI_EXIT_BITMAP_2_HIGH);
    // PRINT_FIELD(VMCS_EOI_EXIT_BITMAP_3_FULL);
    // PRINT_FIELD(VMCS_EOI_EXIT_BITMAP_3_HIGH);
    PRINT_FIELD(VMCS_EPTP_LIST_ADDRESS_FULL);
    PRINT_FIELD(VMCS_EPTP_LIST_ADDRESS_HIGH);
    // PRINT_FIELD(VMCS_VMREAD_BITMAP_ADDRESS_FULL);
    // PRINT_FIELD(VMCS_VMREAD_BITMAP_ADDRESS_HIGH);
    // PRINT_FIELD(VMCS_VMWRITE_BITMAP_ADDRESS_FULL);
    // PRINT_FIELD(VMCS_VMWRITE_BITMAP_ADDRESS_HIGH);
    // PRINT_FIELD(VMCS_VIRTUALIZATION_EXCEPTION_INFORMATION_ADDRESS_FULL);
    // PRINT_FIELD(VMCS_VIRTUALIZATION_EXCEPTION_INFORMATION_ADDRESS_HIGH);
    // PRINT_FIELD(VMCS_XSS_EXITING_BITMAP_FULL);
    // PRINT_FIELD(VMCS_XSS_EXITING_BITMAP_HIGH);

    std::cout << std::endl;
    std::cout << "64bit Read-Only Data Fields:" << std::endl;
    PRINT_FIELD(VMCS_GUEST_PHYSICAL_ADDRESS_FULL);
    PRINT_FIELD(VMCS_GUEST_PHYSICAL_ADDRESS_HIGH);

    std::cout << std::endl;
    std::cout << "64bit Guest State Fields:" << std::endl;
    PRINT_FIELD(VMCS_VMCS_LINK_POINTER_FULL);
    PRINT_FIELD(VMCS_VMCS_LINK_POINTER_HIGH);
    PRINT_FIELD(VMCS_GUEST_IA32_DEBUGCTL_FULL);
    PRINT_FIELD(VMCS_GUEST_IA32_DEBUGCTL_HIGH);
    PRINT_FIELD(VMCS_GUEST_IA32_PAT_FULL);
    PRINT_FIELD(VMCS_GUEST_IA32_PAT_HIGH);
    PRINT_FIELD(VMCS_GUEST_IA32_EFER_FULL);
    PRINT_FIELD(VMCS_GUEST_IA32_EFER_HIGH);
    PRINT_FIELD(VMCS_GUEST_IA32_PERF_GLOBAL_CTRL_FULL);
    PRINT_FIELD(VMCS_GUEST_IA32_PERF_GLOBAL_CTRL_HIGH);
    PRINT_FIELD(VMCS_GUEST_PDPTE0_FULL);
    PRINT_FIELD(VMCS_GUEST_PDPTE0_HIGH);
    PRINT_FIELD(VMCS_GUEST_PDPTE1_FULL);
    PRINT_FIELD(VMCS_GUEST_PDPTE1_HIGH);
    PRINT_FIELD(VMCS_GUEST_PDPTE2_FULL);
    PRINT_FIELD(VMCS_GUEST_PDPTE2_HIGH);
    PRINT_FIELD(VMCS_GUEST_PDPTE3_FULL);
    PRINT_FIELD(VMCS_GUEST_PDPTE3_HIGH);

    std::cout << std::endl;
    std::cout << "64bit Host State Fields:" << std::endl;
    PRINT_FIELD(VMCS_HOST_IA32_PAT_FULL);
    PRINT_FIELD(VMCS_HOST_IA32_PAT_HIGH);
    PRINT_FIELD(VMCS_HOST_IA32_EFER_FULL);
    PRINT_FIELD(VMCS_HOST_IA32_EFER_HIGH);
    PRINT_FIELD(VMCS_HOST_IA32_PERF_GLOBAL_CTRL_FULL);
    PRINT_FIELD(VMCS_HOST_IA32_PERF_GLOBAL_CTRL_HIGH);

    std::cout << std::endl;
    std::cout << "32bit Control Fields:" << std::endl;
    PRINT_FIELD(VMCS_PIN_BASED_VM_EXECUTION_CONTROLS);
    PRINT_FIELD(VMCS_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);
    PRINT_FIELD(VMCS_EXCEPTION_BITMAP);
    PRINT_FIELD(VMCS_PAGE_FAULT_ERROR_CODE_MASK);
    PRINT_FIELD(VMCS_PAGE_FAULT_ERROR_CODE_MATCH);
    PRINT_FIELD(VMCS_CR3_TARGET_COUNT);
    PRINT_FIELD(VMCS_VM_EXIT_CONTROLS);
    PRINT_FIELD(VMCS_VM_EXIT_MSR_STORE_COUNT);
    PRINT_FIELD(VMCS_VM_EXIT_MSR_LOAD_COUNT);
    PRINT_FIELD(VMCS_VM_ENTRY_CONTROLS);
    PRINT_FIELD(VMCS_VM_ENTRY_MSR_LOAD_COUNT);
    PRINT_FIELD(VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD);
    PRINT_FIELD(VMCS_VM_ENTRY_EXCEPTION_ERROR_CODE);
    PRINT_FIELD(VMCS_VM_ENTRY_INSTRUCTION_LENGTH);
    PRINT_FIELD(VMCS_TPR_THRESHOLD);
    PRINT_FIELD(VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);
    // PRINT_FIELD(VMCS_PLE_GAP);
    // PRINT_FIELD(VMCS_PLE_WINDOW);

    std::cout << std::endl;
    std::cout << "32bit Read-Only Fields:" << std::endl;
    PRINT_FIELD(VMCS_VM_INSTRUCTION_ERROR);
    PRINT_FIELD(VMCS_EXIT_REASON);
    PRINT_FIELD(VMCS_VM_EXIT_INTERRUPTION_INFORMATION);
    PRINT_FIELD(VMCS_VM_EXIT_INTERRUPTION_ERROR_CODE);
    PRINT_FIELD(VMCS_IDT_VECTORING_INFORMATION_FIELD);
    PRINT_FIELD(VMCS_IDT_VECTORING_ERROR_CODE);
    PRINT_FIELD(VMCS_VM_EXIT_INSTRUCTION_LENGTH);
    PRINT_FIELD(VMCS_VM_EXIT_INSTRUCTION_INFORMATION);

    std::cout << std::endl;
    std::cout << "32bit Guest State Fields:" << std::endl;
    PRINT_FIELD(VMCS_GUEST_ES_LIMIT);
    PRINT_FIELD(VMCS_GUEST_CS_LIMIT);
    PRINT_FIELD(VMCS_GUEST_SS_LIMIT);
    PRINT_FIELD(VMCS_GUEST_DS_LIMIT);
    PRINT_FIELD(VMCS_GUEST_FS_LIMIT);
    PRINT_FIELD(VMCS_GUEST_GS_LIMIT);
    PRINT_FIELD(VMCS_GUEST_LDTR_LIMIT);
    PRINT_FIELD(VMCS_GUEST_TR_LIMIT);
    PRINT_FIELD(VMCS_GUEST_GDTR_LIMIT);
    PRINT_FIELD(VMCS_GUEST_IDTR_LIMIT);
    PRINT_FIELD(VMCS_GUEST_ES_ACCESS_RIGHTS);
    PRINT_FIELD(VMCS_GUEST_CS_ACCESS_RIGHTS);
    PRINT_FIELD(VMCS_GUEST_SS_ACCESS_RIGHTS);
    PRINT_FIELD(VMCS_GUEST_DS_ACCESS_RIGHTS);
    PRINT_FIELD(VMCS_GUEST_FS_ACCESS_RIGHTS);
    PRINT_FIELD(VMCS_GUEST_GS_ACCESS_RIGHTS);
    PRINT_FIELD(VMCS_GUEST_LDTR_ACCESS_RIGHTS);
    PRINT_FIELD(VMCS_GUEST_TR_ACCESS_RIGHTS);
    PRINT_FIELD(VMCS_GUEST_INTERRUPTIBILITY_STATE);
    PRINT_FIELD(VMCS_GUEST_ACTIVITY_STATE);
    PRINT_FIELD(VMCS_GUEST_SMBASE);
    PRINT_FIELD(VMCS_GUEST_IA32_SYSENTER_CS);
    // PRINT_FIELD(VMCS_VMX_PREEMPTION_TIMER_VALUE);

    std::cout << std::endl;
    std::cout << "32bit Host State Fields:" << std::endl;
    PRINT_FIELD(VMCS_HOST_IA32_SYSENTER_CS);

    std::cout << std::endl;
    std::cout << "Natural Width Control Fields:" << std::endl;
    PRINT_FIELD(VMCS_CR0_GUEST_HOST_MASK);
    PRINT_FIELD(VMCS_CR4_GUEST_HOST_MASK);
    PRINT_FIELD(VMCS_CR0_READ_SHADOW);
    PRINT_FIELD(VMCS_CR4_READ_SHADOW);
    PRINT_FIELD(VMCS_CR3_TARGET_VALUE_0);
    PRINT_FIELD(VMCS_CR3_TARGET_VALUE_1);
    PRINT_FIELD(VMCS_CR3_TARGET_VALUE_2);
    PRINT_FIELD(VMCS_CR3_TARGET_VALUE_31);

    std::cout << std::endl;
    std::cout << "Natural Width Read-Only Fields:" << std::endl;
    PRINT_FIELD(VMCS_EXIT_QUALIFICATION);
    PRINT_FIELD(VMCS_I_O_RCX);
    PRINT_FIELD(VMCS_I_O_RSI);
    PRINT_FIELD(VMCS_I_O_RDI);
    PRINT_FIELD(VMCS_I_O_RIP);
    PRINT_FIELD(VMCS_GUEST_LINEAR_ADDRESS);

    std::cout << std::endl;
    std::cout << "Natural Width Guest State Fields:" << std::endl;
    PRINT_FIELD(VMCS_GUEST_CR0);
    PRINT_FIELD(VMCS_GUEST_CR3);
    PRINT_FIELD(VMCS_GUEST_CR4);
    PRINT_FIELD(VMCS_GUEST_ES_BASE);
    PRINT_FIELD(VMCS_GUEST_CS_BASE);
    PRINT_FIELD(VMCS_GUEST_SS_BASE);
    PRINT_FIELD(VMCS_GUEST_DS_BASE);
    PRINT_FIELD(VMCS_GUEST_FS_BASE);
    PRINT_FIELD(VMCS_GUEST_GS_BASE);
    PRINT_FIELD(VMCS_GUEST_LDTR_BASE);
    PRINT_FIELD(VMCS_GUEST_TR_BASE);
    PRINT_FIELD(VMCS_GUEST_GDTR_BASE);
    PRINT_FIELD(VMCS_GUEST_IDTR_BASE);
    PRINT_FIELD(VMCS_GUEST_DR7);
    PRINT_FIELD(VMCS_GUEST_RSP);
    PRINT_FIELD(VMCS_GUEST_RIP);
    PRINT_FIELD(VMCS_GUEST_RFLAGS);
    PRINT_FIELD(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS);
    PRINT_FIELD(VMCS_GUEST_IA32_SYSENTER_ESP);
    PRINT_FIELD(VMCS_GUEST_IA32_SYSENTER_EIP);

    std::cout << std::endl;
    std::cout << "Natural Width Host State Fields:" << std::endl;
    PRINT_FIELD(VMCS_HOST_CR0);
    PRINT_FIELD(VMCS_HOST_CR3);
    PRINT_FIELD(VMCS_HOST_CR4);
    PRINT_FIELD(VMCS_HOST_FS_BASE);
    PRINT_FIELD(VMCS_HOST_GS_BASE);
    PRINT_FIELD(VMCS_HOST_TR_BASE);
    PRINT_FIELD(VMCS_HOST_GDTR_BASE);
    PRINT_FIELD(VMCS_HOST_IDTR_BASE);
    PRINT_FIELD(VMCS_HOST_IA32_SYSENTER_ESP);
    PRINT_FIELD(VMCS_HOST_IA32_SYSENTER_EIP);
    PRINT_FIELD(VMCS_HOST_RSP);
    PRINT_FIELD(VMCS_HOST_RIP);

    std::cout << std::dec << std::left << std::endl;
}

#define PRINT_STATE(a) \
    std::cout << std::left << std::setw(55) << #a \
              << "0x" << a << std::endl;
void
vmcs_intel_x64::dump_state()
{
    std::cout << std::hex << std::endl;
    std::cout << "State Dump:" << std::endl;
    std::cout << "----------------------------------------------------------------------" << std::endl;

    std::cout << std::endl;
    std::cout << "Segment Selectors:" << std::endl;
    PRINT_STATE(m_es);
    PRINT_STATE(m_cs);
    PRINT_STATE(m_ss);
    PRINT_STATE(m_ds);
    PRINT_STATE(m_fs);
    PRINT_STATE(m_gs);
    PRINT_STATE(m_tr);
    PRINT_STATE(m_ldtr);

    std::cout << std::endl;
    std::cout << "Registers:" << std::endl;
    PRINT_STATE(m_cr0);
    PRINT_STATE(m_cr3);
    PRINT_STATE(m_cr4);
    PRINT_STATE(m_rflags);

    std::cout << std::endl;
    std::cout << "GDT/IDT:" << std::endl;
    PRINT_STATE(m_gdt_reg.limit);
    PRINT_STATE(m_gdt_reg.base);
    PRINT_STATE(m_idt_reg.limit);
    PRINT_STATE(m_idt_reg.base);

    std::cout << std::endl;
    std::cout << "Segment Limit:" << std::endl;
    PRINT_STATE(m_es_limit);
    PRINT_STATE(m_cs_limit);
    PRINT_STATE(m_ss_limit);
    PRINT_STATE(m_ds_limit);
    PRINT_STATE(m_fs_limit);
    PRINT_STATE(m_gs_limit);
    PRINT_STATE(m_ldtr_limit);
    PRINT_STATE(m_tr_limit);

    std::cout << std::endl;
    std::cout << "Segment Access:" << std::endl;
    PRINT_STATE(m_es_access);
    PRINT_STATE(m_cs_access);
    PRINT_STATE(m_ss_access);
    PRINT_STATE(m_ds_access);
    PRINT_STATE(m_fs_access);
    PRINT_STATE(m_gs_access);
    PRINT_STATE(m_ldtr_access);
    PRINT_STATE(m_tr_access);

    std::cout << std::endl;
    std::cout << "Segment Base:" << std::endl;
    PRINT_STATE(m_es_base);
    PRINT_STATE(m_cs_base);
    PRINT_STATE(m_ss_base);
    PRINT_STATE(m_ds_base);
    PRINT_STATE(m_fs_base);
    PRINT_STATE(m_gs_base);
    PRINT_STATE(m_ldtr_base);
    PRINT_STATE(m_tr_base);

    std::cout << std::endl;
    std::cout << "Segment Descriptors:" << std::endl;
    PRINT_STATE(m_intrinsics->segment_descriptor(m_es));
    PRINT_STATE(m_intrinsics->segment_descriptor(m_cs));
    PRINT_STATE(m_intrinsics->segment_descriptor(m_ss));
    PRINT_STATE(m_intrinsics->segment_descriptor(m_ds));
    PRINT_STATE(m_intrinsics->segment_descriptor(m_fs));
    PRINT_STATE(m_intrinsics->segment_descriptor(m_gs));
    PRINT_STATE(m_intrinsics->segment_descriptor(m_ldtr));
    PRINT_STATE(m_intrinsics->segment_descriptor(m_tr));

    std::cout << std::dec << std::left << std::endl;
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
    auto controls = vmread(VMCS_PIN_BASED_VM_EXECUTION_CONTROLS);

    std::cout << std::hex << std::endl;
    std::cout << "Pin-Based VM-Execution Controls:" << std::endl;
    std::cout << "----------------------------------------------------------------------" << std::endl;

    if ((controls & VM_EXEC_PIN_BASED_EXTERNAL_INTERRUPT_EXITING) != 0)
        std::cout << "- " << "VM_EXEC_PIN_BASED_EXTERNAL_INTERRUPT_EXITING" << std::endl;

    if ((controls & VM_EXEC_PIN_BASED_NMI_EXITING) != 0)
        std::cout << "- " << "VM_EXEC_PIN_BASED_NMI_EXITING" << std::endl;

    if ((controls & VM_EXEC_PIN_BASED_VIRTUAL_NMIS) != 0)
        std::cout << "- " << "VM_EXEC_PIN_BASED_VIRTUAL_NMIS" << std::endl;

    if ((controls & VM_EXEC_PIN_BASED_ACTIVATE_VMX_PREEMPTION_TIMER) != 0)
        std::cout << "- " << "VM_EXEC_PIN_BASED_ACTIVATE_VMX_PREEMPTION_TIMER" << std::endl;

    if ((controls & VM_EXEC_PIN_BASED_PROCESS_POSTED_INTERRUPTS) != 0)
        std::cout << "- " << "VM_EXEC_PIN_BASED_PROCESS_POSTED_INTERRUPTS" << std::endl;

    std::cout << std::dec << std::endl;
}

void
vmcs_intel_x64::print_primary_processor_based_vm_execution_controls()
{
    auto controls = vmread(VMCS_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);

    std::cout << std::hex << std::endl;
    std::cout << "Primary Processor-Based VM-Execution Controls:" << std::endl;
    std::cout << "----------------------------------------------------------------------" << std::endl;

    if ((controls & VM_EXEC_P_PROC_BASED_INTERRUPT_WINDOW_EXITING) != 0)
        std::cout << "- " << "VM_EXEC_P_PROC_BASED_INTERRUPT_WINDOW_EXITING" << std::endl;

    if ((controls & VM_EXEC_P_PROC_BASED_USE_TSC_OFFSETTING) != 0)
        std::cout << "- " << "VM_EXEC_P_PROC_BASED_USE_TSC_OFFSETTING" << std::endl;

    if ((controls & VM_EXEC_P_PROC_BASED_HLT_EXITING) != 0)
        std::cout << "- " << "VM_EXEC_P_PROC_BASED_HLT_EXITING" << std::endl;

    if ((controls & VM_EXEC_P_PROC_BASED_INVLPG_EXITING) != 0)
        std::cout << "- " << "VM_EXEC_P_PROC_BASED_INVLPG_EXITING" << std::endl;

    if ((controls & VM_EXEC_P_PROC_BASED_MWAIT_EXITING) != 0)
        std::cout << "- " << "VM_EXEC_P_PROC_BASED_MWAIT_EXITING" << std::endl;

    if ((controls & VM_EXEC_P_PROC_BASED_RDPMC_EXITING) != 0)
        std::cout << "- " << "VM_EXEC_P_PROC_BASED_RDPMC_EXITING" << std::endl;

    if ((controls & VM_EXEC_P_PROC_BASED_RDTSC_EXITING) != 0)
        std::cout << "- " << "VM_EXEC_P_PROC_BASED_RDTSC_EXITING" << std::endl;

    if ((controls & VM_EXEC_P_PROC_BASED_CR3_LOAD_EXITING) != 0)
        std::cout << "- " << "VM_EXEC_P_PROC_BASED_CR3_LOAD_EXITING" << std::endl;

    if ((controls & VM_EXEC_P_PROC_BASED_CR3_STORE_EXITING) != 0)
        std::cout << "- " << "VM_EXEC_P_PROC_BASED_CR3_STORE_EXITING" << std::endl;

    if ((controls & VM_EXEC_P_PROC_BASED_CR8_LOAD_EXITING) != 0)
        std::cout << "- " << "VM_EXEC_P_PROC_BASED_CR8_LOAD_EXITING" << std::endl;

    if ((controls & VM_EXEC_P_PROC_BASED_CR8_STORE_EXITING) != 0)
        std::cout << "- " << "VM_EXEC_P_PROC_BASED_CR8_STORE_EXITING" << std::endl;

    if ((controls & VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW) != 0)
        std::cout << "- " << "VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW" << std::endl;

    if ((controls & VM_EXEC_P_PROC_BASED_NMI_WINDOW_EXITING) != 0)
        std::cout << "- " << "VM_EXEC_P_PROC_BASED_NMI_WINDOW_EXITING" << std::endl;

    if ((controls & VM_EXEC_P_PROC_BASED_MOV_DR_EXITING) != 0)
        std::cout << "- " << "VM_EXEC_P_PROC_BASED_MOV_DR_EXITING" << std::endl;

    if ((controls & VM_EXEC_P_PROC_BASED_UNCONDITIONAL_I_O_EXITING) != 0)
        std::cout << "- " << "VM_EXEC_P_PROC_BASED_UNCONDITIONAL_I_O_EXITING" << std::endl;

    if ((controls & VM_EXEC_P_PROC_BASED_USE_I_O_BITMAPS) != 0)
        std::cout << "- " << "VM_EXEC_P_PROC_BASED_USE_I_O_BITMAPS" << std::endl;

    if ((controls & VM_EXEC_P_PROC_BASED_MONITOR_TRAP_FLAG) != 0)
        std::cout << "- " << "VM_EXEC_P_PROC_BASED_MONITOR_TRAP_FLAG" << std::endl;

    if ((controls & VM_EXEC_P_PROC_BASED_USE_MSR_BITMAPS) != 0)
        std::cout << "- " << "VM_EXEC_P_PROC_BASED_USE_MSR_BITMAPS" << std::endl;

    if ((controls & VM_EXEC_P_PROC_BASED_MONITOR_EXITING) != 0)
        std::cout << "- " << "VM_EXEC_P_PROC_BASED_MONITOR_EXITING" << std::endl;

    if ((controls & VM_EXEC_P_PROC_BASED_PAUSE_EXITING) != 0)
        std::cout << "- " << "VM_EXEC_P_PROC_BASED_PAUSE_EXITING" << std::endl;

    if ((controls & VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS) != 0)
        std::cout << "- " << "VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS" << std::endl;

    std::cout << std::dec << std::endl;
}

void
vmcs_intel_x64::print_secondary_processor_based_vm_execution_controls()
{
    auto controls = vmread(VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);

    std::cout << std::hex << std::endl;
    std::cout << "Secondary Processor-Based VM-Execution Controls:" << std::endl;
    std::cout << "----------------------------------------------------------------------" << std::endl;

    if ((controls & VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES) != 0)
        std::cout << "- " << "VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES" << std::endl;

    if ((controls & VM_EXEC_S_PROC_BASED_ENABLE_EPT) != 0)
        std::cout << "- " << "VM_EXEC_S_PROC_BASED_ENABLE_EPT" << std::endl;

    if ((controls & VM_EXEC_S_PROC_BASED_DESCRIPTOR_TABLE_EXITING) != 0)
        std::cout << "- " << "VM_EXEC_S_PROC_BASED_DESCRIPTOR_TABLE_EXITING" << std::endl;

    if ((controls & VM_EXEC_S_PROC_BASED_ENABLE_RDTSCP) != 0)
        std::cout << "- " << "VM_EXEC_S_PROC_BASED_ENABLE_RDTSCP" << std::endl;

    if ((controls & VM_EXEC_S_PROC_BASED_VIRTUALIZE_X2APIC_MODE) != 0)
        std::cout << "- " << "VM_EXEC_S_PROC_BASED_VIRTUALIZE_X2APIC_MODE" << std::endl;

    if ((controls & VM_EXEC_S_PROC_BASED_ENABLE_VPID) != 0)
        std::cout << "- " << "VM_EXEC_S_PROC_BASED_ENABLE_VPID" << std::endl;

    if ((controls & VM_EXEC_S_PROC_BASED_WBINVD_EXITING) != 0)
        std::cout << "- " << "VM_EXEC_S_PROC_BASED_WBINVD_EXITING" << std::endl;

    if ((controls & VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST) != 0)
        std::cout << "- " << "VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST" << std::endl;

    if ((controls & VM_EXEC_S_PROC_BASED_APIC_REGISTER_VIRTUALIZATION) != 0)
        std::cout << "- " << "VM_EXEC_S_PROC_BASED_APIC_REGISTER_VIRTUALIZATION" << std::endl;

    if ((controls & VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY) != 0)
        std::cout << "- " << "VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY" << std::endl;

    if ((controls & VM_EXEC_S_PROC_BASED_PAUSE_LOOP_EXITING) != 0)
        std::cout << "- " << "VM_EXEC_S_PROC_BASED_PAUSE_LOOP_EXITING" << std::endl;

    if ((controls & VM_EXEC_S_PROC_BASED_RDRAND_EXITING) != 0)
        std::cout << "- " << "VM_EXEC_S_PROC_BASED_RDRAND_EXITING" << std::endl;

    if ((controls & VM_EXEC_S_PROC_BASED_ENABLE_INVPCID) != 0)
        std::cout << "- " << "VM_EXEC_S_PROC_BASED_ENABLE_INVPCID" << std::endl;

    if ((controls & VM_EXEC_S_PROC_BASED_ENABLE_VM_FUNCTIONS) != 0)
        std::cout << "- " << "VM_EXEC_S_PROC_BASED_ENABLE_VM_FUNCTIONS" << std::endl;

    if ((controls & VM_EXEC_S_PROC_BASED_VMCS_SHADOWING) != 0)
        std::cout << "- " << "VM_EXEC_S_PROC_BASED_VMCS_SHADOWING" << std::endl;

    if ((controls & VM_EXEC_S_PROC_BASED_RDSEED_EXITING) != 0)
        std::cout << "- " << "VM_EXEC_S_PROC_BASED_RDSEED_EXITING" << std::endl;

    if ((controls & VM_EXEC_S_PROC_BASED_EPT_VIOLATION_VE) != 0)
        std::cout << "- " << "VM_EXEC_S_PROC_BASED_EPT_VIOLATION_VE" << std::endl;

    if ((controls & VM_EXEC_S_PROC_BASED_ENABLE_XSAVES_XRSTORS) != 0)
        std::cout << "- " << "VM_EXEC_S_PROC_BASED_ENABLE_XSAVES_XRSTORS" << std::endl;

    std::cout << std::dec << std::endl;
}

void
vmcs_intel_x64::print_vm_exit_control_fields()
{
    auto controls = vmread(VMCS_VM_EXIT_CONTROLS);

    std::cout << std::hex << std::endl;
    std::cout << "VM-Exit Controls:" << std::endl;
    std::cout << "----------------------------------------------------------------------" << std::endl;

    if ((controls & VM_EXIT_CONTROL_SAVE_DEBUG_CONTROLS) != 0)
        std::cout << "- " << "VM_EXIT_CONTROL_SAVE_DEBUG_CONTROLS" << std::endl;

    if ((controls & VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE) != 0)
        std::cout << "- " << "VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE" << std::endl;

    if ((controls & VM_EXIT_CONTROL_LOAD_IA32_PERF_GLOBAL_CTRL) != 0)
        std::cout << "- " << "VM_EXIT_CONTROL_LOAD_IA32_PERF_GLOBAL_CTRL" << std::endl;

    if ((controls & VM_EXIT_CONTROL_ACKNOWLEDGE_INTERRUPT_ON_EXIT) != 0)
        std::cout << "- " << "VM_EXIT_CONTROL_ACKNOWLEDGE_INTERRUPT_ON_EXIT" << std::endl;

    if ((controls & VM_EXIT_CONTROL_SAVE_IA32_PAT) != 0)
        std::cout << "- " << "VM_EXIT_CONTROL_SAVE_IA32_PAT" << std::endl;

    if ((controls & VM_EXIT_CONTROL_LOAD_IA32_PAT) != 0)
        std::cout << "- " << "VM_EXIT_CONTROL_LOAD_IA32_PAT" << std::endl;

    if ((controls & VM_EXIT_CONTROL_SAVE_IA32_EFER) != 0)
        std::cout << "- " << "VM_EXIT_CONTROL_SAVE_IA32_EFER" << std::endl;

    if ((controls & VM_EXIT_CONTROL_LOAD_IA32_EFER) != 0)
        std::cout << "- " << "VM_EXIT_CONTROL_LOAD_IA32_EFER" << std::endl;

    if ((controls & VM_EXIT_CONTROL_SAVE_VMX_PREEMPTION_TIMER_VALUE) != 0)
        std::cout << "- " << "VM_EXIT_CONTROL_SAVE_VMX_PREEMPTION_TIMER_VALUE" << std::endl;

    std::cout << std::dec << std::endl;
}

void
vmcs_intel_x64::print_vm_entry_control_fields()
{
    auto controls = vmread(VMCS_VM_ENTRY_CONTROLS);

    std::cout << std::hex << std::endl;
    std::cout << "VM-Entry Controls:" << std::endl;
    std::cout << "----------------------------------------------------------------------" << std::endl;

    if ((controls & VM_ENTRY_CONTROL_LOAD_DEBUG_CONTROLS) != 0)
        std::cout << "- " << "VM_ENTRY_CONTROL_LOAD_DEBUG_CONTROLS" << std::endl;

    if ((controls & VM_ENTRY_CONTROL_IA_32E_MODE_GUEST) != 0)
        std::cout << "- " << "VM_ENTRY_CONTROL_IA_32E_MODE_GUEST" << std::endl;

    if ((controls & VM_ENTRY_CONTROL_ENTRY_TO_SMM) != 0)
        std::cout << "- " << "VM_ENTRY_CONTROL_ENTRY_TO_SMM" << std::endl;

    if ((controls & VM_ENTRY_CONTROL_DEACTIVATE_DUAL_MONITOR_TREATMENT) != 0)
        std::cout << "- " << "VM_ENTRY_CONTROL_DEACTIVATE_DUAL_MONITOR_TREATMENT" << std::endl;

    if ((controls & VM_ENTRY_CONTROL_LOAD_IA32_PERF_GLOBAL_CTRL) != 0)
        std::cout << "- " << "VM_ENTRY_CONTROL_LOAD_IA32_PERF_GLOBAL_CTRL" << std::endl;

    if ((controls & VM_ENTRY_CONTROL_LOAD_IA32_PAT) != 0)
        std::cout << "- " << "VM_ENTRY_CONTROL_LOAD_IA32_PAT" << std::endl;

    if ((controls & VM_ENTRY_CONTROL_LOAD_IA32_EFER) != 0)
        std::cout << "- " << "VM_ENTRY_CONTROL_LOAD_IA32_EFER" << std::endl;

    std::cout << std::dec << std::endl;
}
