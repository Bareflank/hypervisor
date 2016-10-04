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

#include <test.h>
#include <vmcs/vmcs_intel_x64_ftos.h>

#define STRINGIFY_MACRO(a) std::string(#a)

void
vmcs_ut::test_vmcs_field_to_str_valid()
{
    this->expect_true(vmcs_field_to_str(VMCS_VIRTUAL_PROCESSOR_IDENTIFIER) == STRINGIFY_MACRO(VMCS_VIRTUAL_PROCESSOR_IDENTIFIER));
    this->expect_true(vmcs_field_to_str(VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR) == STRINGIFY_MACRO(VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR));
    this->expect_true(vmcs_field_to_str(VMCS_EPTP_INDEX) == STRINGIFY_MACRO(VMCS_EPTP_INDEX));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_ES_SELECTOR) == STRINGIFY_MACRO(VMCS_GUEST_ES_SELECTOR));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_CS_SELECTOR) == STRINGIFY_MACRO(VMCS_GUEST_CS_SELECTOR));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_SS_SELECTOR) == STRINGIFY_MACRO(VMCS_GUEST_SS_SELECTOR));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_DS_SELECTOR) == STRINGIFY_MACRO(VMCS_GUEST_DS_SELECTOR));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_FS_SELECTOR) == STRINGIFY_MACRO(VMCS_GUEST_FS_SELECTOR));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_GS_SELECTOR) == STRINGIFY_MACRO(VMCS_GUEST_GS_SELECTOR));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_LDTR_SELECTOR) == STRINGIFY_MACRO(VMCS_GUEST_LDTR_SELECTOR));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_TR_SELECTOR) == STRINGIFY_MACRO(VMCS_GUEST_TR_SELECTOR));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_INTERRUPT_STATUS) == STRINGIFY_MACRO(VMCS_GUEST_INTERRUPT_STATUS));
    this->expect_true(vmcs_field_to_str(VMCS_HOST_ES_SELECTOR) == STRINGIFY_MACRO(VMCS_HOST_ES_SELECTOR));
    this->expect_true(vmcs_field_to_str(VMCS_HOST_CS_SELECTOR) == STRINGIFY_MACRO(VMCS_HOST_CS_SELECTOR));
    this->expect_true(vmcs_field_to_str(VMCS_HOST_SS_SELECTOR) == STRINGIFY_MACRO(VMCS_HOST_SS_SELECTOR));
    this->expect_true(vmcs_field_to_str(VMCS_HOST_DS_SELECTOR) == STRINGIFY_MACRO(VMCS_HOST_DS_SELECTOR));
    this->expect_true(vmcs_field_to_str(VMCS_HOST_FS_SELECTOR) == STRINGIFY_MACRO(VMCS_HOST_FS_SELECTOR));
    this->expect_true(vmcs_field_to_str(VMCS_HOST_GS_SELECTOR) == STRINGIFY_MACRO(VMCS_HOST_GS_SELECTOR));
    this->expect_true(vmcs_field_to_str(VMCS_HOST_TR_SELECTOR) == STRINGIFY_MACRO(VMCS_HOST_TR_SELECTOR));
    this->expect_true(vmcs_field_to_str(VMCS_ADDRESS_OF_IO_BITMAP_A_FULL) == STRINGIFY_MACRO(VMCS_ADDRESS_OF_IO_BITMAP_A_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_ADDRESS_OF_IO_BITMAP_A_HIGH) == STRINGIFY_MACRO(VMCS_ADDRESS_OF_IO_BITMAP_A_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_ADDRESS_OF_IO_BITMAP_B_FULL) == STRINGIFY_MACRO(VMCS_ADDRESS_OF_IO_BITMAP_B_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_ADDRESS_OF_IO_BITMAP_B_HIGH) == STRINGIFY_MACRO(VMCS_ADDRESS_OF_IO_BITMAP_B_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_ADDRESS_OF_MSR_BITMAPS_FULL) == STRINGIFY_MACRO(VMCS_ADDRESS_OF_MSR_BITMAPS_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_ADDRESS_OF_MSR_BITMAPS_HIGH) == STRINGIFY_MACRO(VMCS_ADDRESS_OF_MSR_BITMAPS_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_VM_EXIT_MSR_STORE_ADDRESS_FULL) == STRINGIFY_MACRO(VMCS_VM_EXIT_MSR_STORE_ADDRESS_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_VM_EXIT_MSR_STORE_ADDRESS_HIGH) == STRINGIFY_MACRO(VMCS_VM_EXIT_MSR_STORE_ADDRESS_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_VM_EXIT_MSR_LOAD_ADDRESS_FULL) == STRINGIFY_MACRO(VMCS_VM_EXIT_MSR_LOAD_ADDRESS_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_VM_EXIT_MSR_LOAD_ADDRESS_HIGH) == STRINGIFY_MACRO(VMCS_VM_EXIT_MSR_LOAD_ADDRESS_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_VM_ENTRY_MSR_LOAD_ADDRESS_FULL) == STRINGIFY_MACRO(VMCS_VM_ENTRY_MSR_LOAD_ADDRESS_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_VM_ENTRY_MSR_LOAD_ADDRESS_HIGH) == STRINGIFY_MACRO(VMCS_VM_ENTRY_MSR_LOAD_ADDRESS_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_EXECUTIVE_VMCS_POINTER_FULL) == STRINGIFY_MACRO(VMCS_EXECUTIVE_VMCS_POINTER_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_EXECUTIVE_VMCS_POINTER_HIGH) == STRINGIFY_MACRO(VMCS_EXECUTIVE_VMCS_POINTER_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_PML_ADDRESS_FULL) == STRINGIFY_MACRO(VMCS_PML_ADDRESS_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_PML_ADDRESS_HIGH) == STRINGIFY_MACRO(VMCS_PML_ADDRESS_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_TSC_OFFSET_FULL) == STRINGIFY_MACRO(VMCS_TSC_OFFSET_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_TSC_OFFSET_HIGH) == STRINGIFY_MACRO(VMCS_TSC_OFFSET_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_VIRTUAL_APIC_ADDRESS_FULL) == STRINGIFY_MACRO(VMCS_VIRTUAL_APIC_ADDRESS_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_VIRTUAL_APIC_ADDRESS_HIGH) == STRINGIFY_MACRO(VMCS_VIRTUAL_APIC_ADDRESS_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_APIC_ACCESS_ADDRESS_FULL) == STRINGIFY_MACRO(VMCS_APIC_ACCESS_ADDRESS_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_APIC_ACCESS_ADDRESS_HIGH) == STRINGIFY_MACRO(VMCS_APIC_ACCESS_ADDRESS_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_FULL) == STRINGIFY_MACRO(VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_HIGH) == STRINGIFY_MACRO(VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_VM_FUNCTION_CONTROLS_FULL) == STRINGIFY_MACRO(VMCS_VM_FUNCTION_CONTROLS_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_VM_FUNCTION_CONTROLS_HIGH) == STRINGIFY_MACRO(VMCS_VM_FUNCTION_CONTROLS_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_EPT_POINTER_FULL) == STRINGIFY_MACRO(VMCS_EPT_POINTER_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_EPT_POINTER_HIGH) == STRINGIFY_MACRO(VMCS_EPT_POINTER_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_EOI_EXIT_BITMAP_0_FULL) == STRINGIFY_MACRO(VMCS_EOI_EXIT_BITMAP_0_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_EOI_EXIT_BITMAP_0_HIGH) == STRINGIFY_MACRO(VMCS_EOI_EXIT_BITMAP_0_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_EOI_EXIT_BITMAP_1_FULL) == STRINGIFY_MACRO(VMCS_EOI_EXIT_BITMAP_1_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_EOI_EXIT_BITMAP_1_HIGH) == STRINGIFY_MACRO(VMCS_EOI_EXIT_BITMAP_1_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_EOI_EXIT_BITMAP_2_FULL) == STRINGIFY_MACRO(VMCS_EOI_EXIT_BITMAP_2_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_EOI_EXIT_BITMAP_2_HIGH) == STRINGIFY_MACRO(VMCS_EOI_EXIT_BITMAP_2_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_EOI_EXIT_BITMAP_3_FULL) == STRINGIFY_MACRO(VMCS_EOI_EXIT_BITMAP_3_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_EOI_EXIT_BITMAP_3_HIGH) == STRINGIFY_MACRO(VMCS_EOI_EXIT_BITMAP_3_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_EPTP_LIST_ADDRESS_FULL) == STRINGIFY_MACRO(VMCS_EPTP_LIST_ADDRESS_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_EPTP_LIST_ADDRESS_HIGH) == STRINGIFY_MACRO(VMCS_EPTP_LIST_ADDRESS_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_VMREAD_BITMAP_ADDRESS_FULL) == STRINGIFY_MACRO(VMCS_VMREAD_BITMAP_ADDRESS_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_VMREAD_BITMAP_ADDRESS_HIGH) == STRINGIFY_MACRO(VMCS_VMREAD_BITMAP_ADDRESS_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_VMWRITE_BITMAP_ADDRESS_FULL) == STRINGIFY_MACRO(VMCS_VMWRITE_BITMAP_ADDRESS_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_VMWRITE_BITMAP_ADDRESS_HIGH) == STRINGIFY_MACRO(VMCS_VMWRITE_BITMAP_ADDRESS_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_VIRTUALIZATION_EXCEPTION_INFORMATION_ADDRESS_FULL) == STRINGIFY_MACRO(VMCS_VIRTUALIZATION_EXCEPTION_INFORMATION_ADDRESS_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_VIRTUALIZATION_EXCEPTION_INFORMATION_ADDRESS_HIGH) == STRINGIFY_MACRO(VMCS_VIRTUALIZATION_EXCEPTION_INFORMATION_ADDRESS_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_XSS_EXITING_BITMAP_FULL) == STRINGIFY_MACRO(VMCS_XSS_EXITING_BITMAP_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_XSS_EXITING_BITMAP_HIGH) == STRINGIFY_MACRO(VMCS_XSS_EXITING_BITMAP_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_PHYSICAL_ADDRESS_FULL) == STRINGIFY_MACRO(VMCS_GUEST_PHYSICAL_ADDRESS_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_PHYSICAL_ADDRESS_HIGH) == STRINGIFY_MACRO(VMCS_GUEST_PHYSICAL_ADDRESS_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_VMCS_LINK_POINTER_FULL) == STRINGIFY_MACRO(VMCS_VMCS_LINK_POINTER_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_VMCS_LINK_POINTER_HIGH) == STRINGIFY_MACRO(VMCS_VMCS_LINK_POINTER_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_IA32_DEBUGCTL_FULL) == STRINGIFY_MACRO(VMCS_GUEST_IA32_DEBUGCTL_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_IA32_DEBUGCTL_HIGH) == STRINGIFY_MACRO(VMCS_GUEST_IA32_DEBUGCTL_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_IA32_PAT_FULL) == STRINGIFY_MACRO(VMCS_GUEST_IA32_PAT_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_IA32_PAT_HIGH) == STRINGIFY_MACRO(VMCS_GUEST_IA32_PAT_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_IA32_EFER_FULL) == STRINGIFY_MACRO(VMCS_GUEST_IA32_EFER_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_IA32_EFER_HIGH) == STRINGIFY_MACRO(VMCS_GUEST_IA32_EFER_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_IA32_PERF_GLOBAL_CTRL_FULL) == STRINGIFY_MACRO(VMCS_GUEST_IA32_PERF_GLOBAL_CTRL_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_IA32_PERF_GLOBAL_CTRL_HIGH) == STRINGIFY_MACRO(VMCS_GUEST_IA32_PERF_GLOBAL_CTRL_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_PDPTE0_FULL) == STRINGIFY_MACRO(VMCS_GUEST_PDPTE0_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_PDPTE0_HIGH) == STRINGIFY_MACRO(VMCS_GUEST_PDPTE0_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_PDPTE1_FULL) == STRINGIFY_MACRO(VMCS_GUEST_PDPTE1_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_PDPTE1_HIGH) == STRINGIFY_MACRO(VMCS_GUEST_PDPTE1_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_PDPTE2_FULL) == STRINGIFY_MACRO(VMCS_GUEST_PDPTE2_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_PDPTE2_HIGH) == STRINGIFY_MACRO(VMCS_GUEST_PDPTE2_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_PDPTE3_FULL) == STRINGIFY_MACRO(VMCS_GUEST_PDPTE3_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_PDPTE3_HIGH) == STRINGIFY_MACRO(VMCS_GUEST_PDPTE3_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_HOST_IA32_PAT_FULL) == STRINGIFY_MACRO(VMCS_HOST_IA32_PAT_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_HOST_IA32_PAT_HIGH) == STRINGIFY_MACRO(VMCS_HOST_IA32_PAT_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_HOST_IA32_EFER_FULL) == STRINGIFY_MACRO(VMCS_HOST_IA32_EFER_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_HOST_IA32_EFER_HIGH) == STRINGIFY_MACRO(VMCS_HOST_IA32_EFER_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_HOST_IA32_PERF_GLOBAL_CTRL_FULL) == STRINGIFY_MACRO(VMCS_HOST_IA32_PERF_GLOBAL_CTRL_FULL));
    this->expect_true(vmcs_field_to_str(VMCS_HOST_IA32_PERF_GLOBAL_CTRL_HIGH) == STRINGIFY_MACRO(VMCS_HOST_IA32_PERF_GLOBAL_CTRL_HIGH));
    this->expect_true(vmcs_field_to_str(VMCS_PIN_BASED_VM_EXECUTION_CONTROLS) == STRINGIFY_MACRO(VMCS_PIN_BASED_VM_EXECUTION_CONTROLS));
    this->expect_true(vmcs_field_to_str(VMCS_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS) == STRINGIFY_MACRO(VMCS_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS));
    this->expect_true(vmcs_field_to_str(VMCS_EXCEPTION_BITMAP) == STRINGIFY_MACRO(VMCS_EXCEPTION_BITMAP));
    this->expect_true(vmcs_field_to_str(VMCS_PAGE_FAULT_ERROR_CODE_MASK) == STRINGIFY_MACRO(VMCS_PAGE_FAULT_ERROR_CODE_MASK));
    this->expect_true(vmcs_field_to_str(VMCS_PAGE_FAULT_ERROR_CODE_MATCH) == STRINGIFY_MACRO(VMCS_PAGE_FAULT_ERROR_CODE_MATCH));
    this->expect_true(vmcs_field_to_str(VMCS_CR3_TARGET_COUNT) == STRINGIFY_MACRO(VMCS_CR3_TARGET_COUNT));
    this->expect_true(vmcs_field_to_str(VMCS_VM_EXIT_CONTROLS) == STRINGIFY_MACRO(VMCS_VM_EXIT_CONTROLS));
    this->expect_true(vmcs_field_to_str(VMCS_VM_EXIT_MSR_STORE_COUNT) == STRINGIFY_MACRO(VMCS_VM_EXIT_MSR_STORE_COUNT));
    this->expect_true(vmcs_field_to_str(VMCS_VM_EXIT_MSR_LOAD_COUNT) == STRINGIFY_MACRO(VMCS_VM_EXIT_MSR_LOAD_COUNT));
    this->expect_true(vmcs_field_to_str(VMCS_VM_ENTRY_CONTROLS) == STRINGIFY_MACRO(VMCS_VM_ENTRY_CONTROLS));
    this->expect_true(vmcs_field_to_str(VMCS_VM_ENTRY_MSR_LOAD_COUNT) == STRINGIFY_MACRO(VMCS_VM_ENTRY_MSR_LOAD_COUNT));
    this->expect_true(vmcs_field_to_str(VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD) == STRINGIFY_MACRO(VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD));
    this->expect_true(vmcs_field_to_str(VMCS_VM_ENTRY_EXCEPTION_ERROR_CODE) == STRINGIFY_MACRO(VMCS_VM_ENTRY_EXCEPTION_ERROR_CODE));
    this->expect_true(vmcs_field_to_str(VMCS_VM_ENTRY_INSTRUCTION_LENGTH) == STRINGIFY_MACRO(VMCS_VM_ENTRY_INSTRUCTION_LENGTH));
    this->expect_true(vmcs_field_to_str(VMCS_TPR_THRESHOLD) == STRINGIFY_MACRO(VMCS_TPR_THRESHOLD));
    this->expect_true(vmcs_field_to_str(VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS) == STRINGIFY_MACRO(VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS));
    this->expect_true(vmcs_field_to_str(VMCS_PLE_GAP) == STRINGIFY_MACRO(VMCS_PLE_GAP));
    this->expect_true(vmcs_field_to_str(VMCS_PLE_WINDOW) == STRINGIFY_MACRO(VMCS_PLE_WINDOW));
    this->expect_true(vmcs_field_to_str(VMCS_VM_INSTRUCTION_ERROR) == STRINGIFY_MACRO(VMCS_VM_INSTRUCTION_ERROR));
    this->expect_true(vmcs_field_to_str(VMCS_EXIT_REASON) == STRINGIFY_MACRO(VMCS_EXIT_REASON));
    this->expect_true(vmcs_field_to_str(VMCS_VM_EXIT_INTERRUPTION_INFORMATION) == STRINGIFY_MACRO(VMCS_VM_EXIT_INTERRUPTION_INFORMATION));
    this->expect_true(vmcs_field_to_str(VMCS_VM_EXIT_INTERRUPTION_ERROR_CODE) == STRINGIFY_MACRO(VMCS_VM_EXIT_INTERRUPTION_ERROR_CODE));
    this->expect_true(vmcs_field_to_str(VMCS_IDT_VECTORING_INFORMATION_FIELD) == STRINGIFY_MACRO(VMCS_IDT_VECTORING_INFORMATION_FIELD));
    this->expect_true(vmcs_field_to_str(VMCS_IDT_VECTORING_ERROR_CODE) == STRINGIFY_MACRO(VMCS_IDT_VECTORING_ERROR_CODE));
    this->expect_true(vmcs_field_to_str(VMCS_VM_EXIT_INSTRUCTION_LENGTH) == STRINGIFY_MACRO(VMCS_VM_EXIT_INSTRUCTION_LENGTH));
    this->expect_true(vmcs_field_to_str(VMCS_VM_EXIT_INSTRUCTION_INFORMATION) == STRINGIFY_MACRO(VMCS_VM_EXIT_INSTRUCTION_INFORMATION));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_ES_LIMIT) == STRINGIFY_MACRO(VMCS_GUEST_ES_LIMIT));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_CS_LIMIT) == STRINGIFY_MACRO(VMCS_GUEST_CS_LIMIT));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_SS_LIMIT) == STRINGIFY_MACRO(VMCS_GUEST_SS_LIMIT));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_DS_LIMIT) == STRINGIFY_MACRO(VMCS_GUEST_DS_LIMIT));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_FS_LIMIT) == STRINGIFY_MACRO(VMCS_GUEST_FS_LIMIT));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_GS_LIMIT) == STRINGIFY_MACRO(VMCS_GUEST_GS_LIMIT));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_LDTR_LIMIT) == STRINGIFY_MACRO(VMCS_GUEST_LDTR_LIMIT));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_TR_LIMIT) == STRINGIFY_MACRO(VMCS_GUEST_TR_LIMIT));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_GDTR_LIMIT) == STRINGIFY_MACRO(VMCS_GUEST_GDTR_LIMIT));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_IDTR_LIMIT) == STRINGIFY_MACRO(VMCS_GUEST_IDTR_LIMIT));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_ES_ACCESS_RIGHTS) == STRINGIFY_MACRO(VMCS_GUEST_ES_ACCESS_RIGHTS));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_CS_ACCESS_RIGHTS) == STRINGIFY_MACRO(VMCS_GUEST_CS_ACCESS_RIGHTS));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_SS_ACCESS_RIGHTS) == STRINGIFY_MACRO(VMCS_GUEST_SS_ACCESS_RIGHTS));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_DS_ACCESS_RIGHTS) == STRINGIFY_MACRO(VMCS_GUEST_DS_ACCESS_RIGHTS));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_FS_ACCESS_RIGHTS) == STRINGIFY_MACRO(VMCS_GUEST_FS_ACCESS_RIGHTS));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_GS_ACCESS_RIGHTS) == STRINGIFY_MACRO(VMCS_GUEST_GS_ACCESS_RIGHTS));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_LDTR_ACCESS_RIGHTS) == STRINGIFY_MACRO(VMCS_GUEST_LDTR_ACCESS_RIGHTS));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_TR_ACCESS_RIGHTS) == STRINGIFY_MACRO(VMCS_GUEST_TR_ACCESS_RIGHTS));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_INTERRUPTIBILITY_STATE) == STRINGIFY_MACRO(VMCS_GUEST_INTERRUPTIBILITY_STATE));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_ACTIVITY_STATE) == STRINGIFY_MACRO(VMCS_GUEST_ACTIVITY_STATE));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_SMBASE) == STRINGIFY_MACRO(VMCS_GUEST_SMBASE));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_IA32_SYSENTER_CS) == STRINGIFY_MACRO(VMCS_GUEST_IA32_SYSENTER_CS));
    this->expect_true(vmcs_field_to_str(VMCS_VMX_PREEMPTION_TIMER_VALUE) == STRINGIFY_MACRO(VMCS_VMX_PREEMPTION_TIMER_VALUE));
    this->expect_true(vmcs_field_to_str(VMCS_HOST_IA32_SYSENTER_CS) == STRINGIFY_MACRO(VMCS_HOST_IA32_SYSENTER_CS));
    this->expect_true(vmcs_field_to_str(VMCS_CR0_GUEST_HOST_MASK) == STRINGIFY_MACRO(VMCS_CR0_GUEST_HOST_MASK));
    this->expect_true(vmcs_field_to_str(VMCS_CR4_GUEST_HOST_MASK) == STRINGIFY_MACRO(VMCS_CR4_GUEST_HOST_MASK));
    this->expect_true(vmcs_field_to_str(VMCS_CR0_READ_SHADOW) == STRINGIFY_MACRO(VMCS_CR0_READ_SHADOW));
    this->expect_true(vmcs_field_to_str(VMCS_CR4_READ_SHADOW) == STRINGIFY_MACRO(VMCS_CR4_READ_SHADOW));
    this->expect_true(vmcs_field_to_str(VMCS_CR3_TARGET_VALUE_0) == STRINGIFY_MACRO(VMCS_CR3_TARGET_VALUE_0));
    this->expect_true(vmcs_field_to_str(VMCS_CR3_TARGET_VALUE_1) == STRINGIFY_MACRO(VMCS_CR3_TARGET_VALUE_1));
    this->expect_true(vmcs_field_to_str(VMCS_CR3_TARGET_VALUE_2) == STRINGIFY_MACRO(VMCS_CR3_TARGET_VALUE_2));
    this->expect_true(vmcs_field_to_str(VMCS_CR3_TARGET_VALUE_31) == STRINGIFY_MACRO(VMCS_CR3_TARGET_VALUE_31));
    this->expect_true(vmcs_field_to_str(VMCS_EXIT_QUALIFICATION) == STRINGIFY_MACRO(VMCS_EXIT_QUALIFICATION));
    this->expect_true(vmcs_field_to_str(VMCS_IO_RCX) == STRINGIFY_MACRO(VMCS_IO_RCX));
    this->expect_true(vmcs_field_to_str(VMCS_IO_RSI) == STRINGIFY_MACRO(VMCS_IO_RSI));
    this->expect_true(vmcs_field_to_str(VMCS_IO_RDI) == STRINGIFY_MACRO(VMCS_IO_RDI));
    this->expect_true(vmcs_field_to_str(VMCS_IO_RIP) == STRINGIFY_MACRO(VMCS_IO_RIP));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_LINEAR_ADDRESS) == STRINGIFY_MACRO(VMCS_GUEST_LINEAR_ADDRESS));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_CR0) == STRINGIFY_MACRO(VMCS_GUEST_CR0));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_CR3) == STRINGIFY_MACRO(VMCS_GUEST_CR3));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_CR4) == STRINGIFY_MACRO(VMCS_GUEST_CR4));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_ES_BASE) == STRINGIFY_MACRO(VMCS_GUEST_ES_BASE));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_CS_BASE) == STRINGIFY_MACRO(VMCS_GUEST_CS_BASE));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_SS_BASE) == STRINGIFY_MACRO(VMCS_GUEST_SS_BASE));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_DS_BASE) == STRINGIFY_MACRO(VMCS_GUEST_DS_BASE));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_FS_BASE) == STRINGIFY_MACRO(VMCS_GUEST_FS_BASE));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_GS_BASE) == STRINGIFY_MACRO(VMCS_GUEST_GS_BASE));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_LDTR_BASE) == STRINGIFY_MACRO(VMCS_GUEST_LDTR_BASE));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_TR_BASE) == STRINGIFY_MACRO(VMCS_GUEST_TR_BASE));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_GDTR_BASE) == STRINGIFY_MACRO(VMCS_GUEST_GDTR_BASE));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_IDTR_BASE) == STRINGIFY_MACRO(VMCS_GUEST_IDTR_BASE));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_DR7) == STRINGIFY_MACRO(VMCS_GUEST_DR7));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_RSP) == STRINGIFY_MACRO(VMCS_GUEST_RSP));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_RIP) == STRINGIFY_MACRO(VMCS_GUEST_RIP));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_RFLAGS) == STRINGIFY_MACRO(VMCS_GUEST_RFLAGS));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS) == STRINGIFY_MACRO(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_IA32_SYSENTER_ESP) == STRINGIFY_MACRO(VMCS_GUEST_IA32_SYSENTER_ESP));
    this->expect_true(vmcs_field_to_str(VMCS_GUEST_IA32_SYSENTER_EIP) == STRINGIFY_MACRO(VMCS_GUEST_IA32_SYSENTER_EIP));
    this->expect_true(vmcs_field_to_str(VMCS_HOST_CR0) == STRINGIFY_MACRO(VMCS_HOST_CR0));
    this->expect_true(vmcs_field_to_str(VMCS_HOST_CR3) == STRINGIFY_MACRO(VMCS_HOST_CR3));
    this->expect_true(vmcs_field_to_str(VMCS_HOST_CR4) == STRINGIFY_MACRO(VMCS_HOST_CR4));
    this->expect_true(vmcs_field_to_str(VMCS_HOST_FS_BASE) == STRINGIFY_MACRO(VMCS_HOST_FS_BASE));
    this->expect_true(vmcs_field_to_str(VMCS_HOST_GS_BASE) == STRINGIFY_MACRO(VMCS_HOST_GS_BASE));
    this->expect_true(vmcs_field_to_str(VMCS_HOST_TR_BASE) == STRINGIFY_MACRO(VMCS_HOST_TR_BASE));
    this->expect_true(vmcs_field_to_str(VMCS_HOST_GDTR_BASE) == STRINGIFY_MACRO(VMCS_HOST_GDTR_BASE));
    this->expect_true(vmcs_field_to_str(VMCS_HOST_IDTR_BASE) == STRINGIFY_MACRO(VMCS_HOST_IDTR_BASE));
    this->expect_true(vmcs_field_to_str(VMCS_HOST_IA32_SYSENTER_ESP) == STRINGIFY_MACRO(VMCS_HOST_IA32_SYSENTER_ESP));
    this->expect_true(vmcs_field_to_str(VMCS_HOST_IA32_SYSENTER_EIP) == STRINGIFY_MACRO(VMCS_HOST_IA32_SYSENTER_EIP));
    this->expect_true(vmcs_field_to_str(VMCS_HOST_RSP) == STRINGIFY_MACRO(VMCS_HOST_RSP));
    this->expect_true(vmcs_field_to_str(VMCS_HOST_RIP) == STRINGIFY_MACRO(VMCS_HOST_RIP));
}

void
vmcs_ut::test_vmcs_field_to_str_unknown()
{
    this->expect_true(vmcs_field_to_str(0x123456789) == std::string("UNDEFINED_VMCS_FIELD"));
}
