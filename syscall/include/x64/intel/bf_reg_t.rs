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

/// @brief defines the rax register
const BF_REG_T_RAX:u64 = 1;
/// @brief defines the rbx register
const BF_REG_T_RBX:u64 = 2;
/// @brief defines the rcx register
const BF_REG_T_RCX:u64 = 3;
/// @brief defines the rdx register
const BF_REG_T_RDX:u64 = 4;
/// @brief defines the rbp register
const BF_REG_T_RBP:u64 = 5;
/// @brief defines the rsi register
const BF_REG_T_RSI:u64 = 6;
/// @brief defines the rdi register
const BF_REG_T_RDI:u64 = 7;
/// @brief defines the r8 register
const BF_REG_T_R8:u64 = 8;
/// @brief defines the r9 register
const BF_REG_T_R9:u64 = 9;
/// @brief defines the r10 register
const BF_REG_T_R10:u64 = 10;
/// @brief defines the r11 register
const BF_REG_T_R11:u64 = 11;
/// @brief defines the r12 register
const BF_REG_T_R12:u64 = 12;
/// @brief defines the r13 register
const BF_REG_T_R13:u64 = 13;
/// @brief defines the r14 register
const BF_REG_T_R14:u64 = 14;
/// @brief defines the r15 register
const BF_REG_T_R15:u64 = 15;
/// @brief defines the bf_reg_t_guest_cr2 register
const BF_REG_T_GUEST_CR2:u64 = 16;
/// @brief defines the bf_reg_t_guest_dr6 register
const BF_REG_T_GUEST_DR6:u64 = 17;
/// @brief defines the bf_reg_t_guest_star register
const BF_REG_T_GUEST_STAR:u64 = 18;
/// @brief defines the bf_reg_t_guest_lstar register
const BF_REG_T_GUEST_LSTAR:u64 = 19;
/// @brief defines the bf_reg_t_guest_cstar register
const BF_REG_T_GUEST_CSTAR:u64 = 20;
/// @brief defines the bf_reg_t_guest_fmask register
const BF_REG_T_GUEST_FMASK:u64 = 21;
/// @brief defines the bf_reg_t_guest_kernel_gs_base register
const BF_REG_T_GUEST_KERNEL_GS_BASE:u64 = 22;
/// @brief defines the virtual_processor_identifier register
const BF_REG_T_VIRTUAL_PROCESSOR_IDENTIFIER:u64 = 23;
/// @brief defines the posted_interrupt_notification_vector register
const BF_REG_T_POSTED_INTERRUPT_NOTIFICATION_VECTOR:u64 = 24;
/// @brief defines the eptp_index register
const BF_REG_T_EPTP_INDEX:u64 = 25;
/// @brief defines the guest_es_selector register
const BF_REG_T_GUEST_ES_SELECTOR:u64 = 26;
/// @brief defines the guest_cs_selector register
const BF_REG_T_GUEST_CS_SELECTOR:u64 = 27;
/// @brief defines the guest_ss_selector register
const BF_REG_T_GUEST_SS_SELECTOR:u64 = 28;
/// @brief defines the guest_ds_selector register
const BF_REG_T_GUEST_DS_SELECTOR:u64 = 29;
/// @brief defines the guest_fs_selector register
const BF_REG_T_GUEST_FS_SELECTOR:u64 = 30;
/// @brief defines the guest_gs_selector register
const BF_REG_T_GUEST_GS_SELECTOR:u64 = 31;
/// @brief defines the guest_ldtr_selector register
const BF_REG_T_GUEST_LDTR_SELECTOR:u64 = 32;
/// @brief defines the guest_tr_selector register
const BF_REG_T_GUEST_TR_SELECTOR:u64 = 33;
/// @brief defines the guest_interrupt_status register
const BF_REG_T_GUEST_INTERRUPT_STATUS:u64 = 34;
/// @brief defines the pml_index register
const BF_REG_T_PML_INDEX:u64 = 35;
/// @brief defines the address_of_io_bitmap_a register
const BF_REG_T_ADDRESS_OF_IO_BITMAP_A:u64 = 36;
/// @brief defines the address_of_io_bitmap_b register
const BF_REG_T_ADDRESS_OF_IO_BITMAP_B:u64 = 37;
/// @brief defines the address_of_msr_bitmaps register
const BF_REG_T_ADDRESS_OF_MSR_BITMAPS:u64 = 38;
/// @brief defines the vmexit_msr_store_address register
const BF_REG_T_VMEXIT_MSR_STORE_ADDRESS:u64 = 39;
/// @brief defines the vmexit_msr_load_address register
const BF_REG_T_VMEXIT_MSR_LOAD_ADDRESS:u64 = 40;
/// @brief defines the vmentry_msr_load_address register
const BF_REG_T_VMENTRY_MSR_LOAD_ADDRESS:u64 = 41;
/// @brief defines the executive_vmcs_pointer register
const BF_REG_T_EXECUTIVE_VMCS_POINTER:u64 = 42;
/// @brief defines the pml_address register
const BF_REG_T_PML_ADDRESS:u64 = 43;
/// @brief defines the tsc_offset register
const BF_REG_T_TSC_OFFSET:u64 = 44;
/// @brief defines the virtual_apic_address register
const BF_REG_T_VIRTUAL_APIC_ADDRESS:u64 = 45;
/// @brief defines the apic_access_address register
const BF_REG_T_APIC_ACCESS_ADDRESS:u64 = 46;
/// @brief defines the posted_interrupt_descriptor_address register
const BF_REG_T_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS:u64 = 47;
/// @brief defines the vm_function_controls register
const BF_REG_T_VM_FUNCTION_CONTROLS:u64 = 48;
/// @brief defines the ept_pointer register
const BF_REG_T_EPT_POINTER:u64 = 49;
/// @brief defines the eoi_exit_bitmap0 register
const BF_REG_T_EOI_EXIT_BITMAP0:u64 = 50;
/// @brief defines the eoi_exit_bitmap1 register
const BF_REG_T_EOI_EXIT_BITMAP1:u64 = 51;
/// @brief defines the eoi_exit_bitmap2 register
const BF_REG_T_EOI_EXIT_BITMAP2:u64 = 52;
/// @brief defines the eoi_exit_bitmap3 register
const BF_REG_T_EOI_EXIT_BITMAP3:u64 = 53;
/// @brief defines the eptp_list_address register
const BF_REG_T_EPTP_LIST_ADDRESS:u64 = 54;
/// @brief defines the vmread_bitmap_address register
const BF_REG_T_VMREAD_BITMAP_ADDRESS:u64 = 55;
/// @brief defines the vmwrite_bitmap_address register
const BF_REG_T_VMWRITE_BITMAP_ADDRESS:u64 = 56;
/// @brief defines the virt_exception_information_address register
const BF_REG_T_VIRT_EXCEPTION_INFORMATION_ADDRESS:u64 = 57;
/// @brief defines the xss_exiting_bitmap register
const BF_REG_T_XSS_EXITING_BITMAP:u64 = 58;
/// @brief defines the encls_exiting_bitmap register
const BF_REG_T_ENCLS_EXITING_BITMAP:u64 = 59;
/// @brief defines the sub_page_permission_table_pointer register
const BF_REG_T_SUB_PAGE_PERMISSION_TABLE_POINTER:u64 = 60;
/// @brief defines the tls_multiplier register
const BF_REG_T_TLS_MULTIPLIER:u64 = 61;
/// @brief defines the guest_physical_address register
const BF_REG_T_GUEST_PHYSICAL_ADDRESS:u64 = 62;
/// @brief defines the vmcs_link_pointer register
const BF_REG_T_VMCS_LINK_POINTER:u64 = 63;
/// @brief defines the guest_debugctl register
const BF_REG_T_GUEST_DEBUGCTL:u64 = 64;
/// @brief defines the guest_pat register
const BF_REG_T_GUEST_PAT:u64 = 65;
/// @brief defines the guest_efer register
const BF_REG_T_GUEST_EFER:u64 = 66;
/// @brief defines the guest_perf_global_ctrl register
const BF_REG_T_GUEST_PERF_GLOBAL_CTRL:u64 = 67;
/// @brief defines the guest_pdpte0 register
const BF_REG_T_GUEST_PDPTE0:u64 = 68;
/// @brief defines the guest_pdpte1 register
const BF_REG_T_GUEST_PDPTE1:u64 = 69;
/// @brief defines the guest_pdpte2 register
const BF_REG_T_GUEST_PDPTE2:u64 = 70;
/// @brief defines the guest_pdpte3 register
const BF_REG_T_GUEST_PDPTE3:u64 = 71;
/// @brief defines the guest_bndcfgs register
const BF_REG_T_GUEST_BNDCFGS:u64 = 72;
/// @brief defines the guest_rtit_ctl register
const BF_REG_T_GUEST_RTIT_CTL:u64 = 73;
/// @brief defines the pin_based_vm_execution_ctls register
const BF_REG_T_PIN_BASED_VM_EXECUTION_CTLS:u64 = 74;
/// @brief defines the primary_proc_based_vm_execution_ctls register
const BF_REG_T_PRIMARY_PROC_BASED_VM_EXECUTION_CTLS:u64 = 75;
/// @brief defines the exception_bitmap register
const BF_REG_T_EXCEPTION_BITMAP:u64 = 76;
/// @brief defines the page_fault_error_code_mask register
const BF_REG_T_PAGE_FAULT_ERROR_CODE_MASK:u64 = 77;
/// @brief defines the page_fault_error_code_match register
const BF_REG_T_PAGE_FAULT_ERROR_CODE_MATCH:u64 = 78;
/// @brief defines the cr3_target_count register
const BF_REG_T_CR3_TARGET_COUNT:u64 = 79;
/// @brief defines the vmexit_ctls register
const BF_REG_T_VMEXIT_CTLS:u64 = 80;
/// @brief defines the vmexit_msr_store_count register
const BF_REG_T_VMEXIT_MSR_STORE_COUNT:u64 = 81;
/// @brief defines the vmexit_msr_load_count register
const BF_REG_T_VMEXIT_MSR_LOAD_COUNT:u64 = 82;
/// @brief defines the vmentry_ctls register
const BF_REG_T_VMENTRY_CTLS:u64 = 83;
/// @brief defines the vmentry_msr_load_count register
const BF_REG_T_VMENTRY_MSR_LOAD_COUNT:u64 = 84;
/// @brief defines the vmentry_interrupt_information_field register
const BF_REG_T_VMENTRY_INTERRUPT_INFORMATION_FIELD:u64 = 85;
/// @brief defines the vmentry_exception_error_code register
const BF_REG_T_VMENTRY_EXCEPTION_ERROR_CODE:u64 = 86;
/// @brief defines the vmentry_instruction_length register
const BF_REG_T_VMENTRY_INSTRUCTION_LENGTH:u64 = 87;
/// @brief defines the tpr_threshold register
const BF_REG_T_TPR_THRESHOLD:u64 = 88;
/// @brief defines the secondary_proc_based_vm_execution_ctls register
const BF_REG_T_SECONDARY_PROC_BASED_VM_EXECUTION_CTLS:u64 = 89;
/// @brief defines the ple_gap register
const BF_REG_T_PLE_GAP:u64 = 90;
/// @brief defines the ple_window register
const BF_REG_T_PLE_WINDOW:u64 = 91;
/// @brief defines the vm_instruction_error register
const BF_REG_T_VM_INSTRUCTION_ERROR:u64 = 92;
/// @brief defines the exit_reason register
const BF_REG_T_EXIT_REASON:u64 = 93;
/// @brief defines the vmexit_interruption_information register
const BF_REG_T_VMEXIT_INTERRUPTION_INFORMATION:u64 = 94;
/// @brief defines the vmexit_interruption_error_code register
const BF_REG_T_VMEXIT_INTERRUPTION_ERROR_CODE:u64 = 95;
/// @brief defines the idt_vectoring_information_field register
const BF_REG_T_IDT_VECTORING_INFORMATION_FIELD:u64 = 96;
/// @brief defines the idt_vectoring_error_code register
const BF_REG_T_IDT_VECTORING_ERROR_CODE:u64 = 97;
/// @brief defines the vmexit_instruction_length register
const BF_REG_T_VMEXIT_INSTRUCTION_LENGTH:u64 = 98;
/// @brief defines the vmexit_instruction_information register
const BF_REG_T_VMEXIT_INSTRUCTION_INFORMATION:u64 = 99;
/// @brief defines the guest_es_limit register
const BF_REG_T_GUEST_ES_LIMIT:u64 = 100;
/// @brief defines the guest_cs_limit register
const BF_REG_T_GUEST_CS_LIMIT:u64 = 101;
/// @brief defines the guest_ss_limit register
const BF_REG_T_GUEST_SS_LIMIT:u64 = 102;
/// @brief defines the guest_ds_limit register
const BF_REG_T_GUEST_DS_LIMIT:u64 = 103;
/// @brief defines the guest_fs_limit register
const BF_REG_T_GUEST_FS_LIMIT:u64 = 104;
/// @brief defines the guest_gs_limit register
const BF_REG_T_GUEST_GS_LIMIT:u64 = 105;
/// @brief defines the guest_ldtr_limit register
const BF_REG_T_GUEST_LDTR_LIMIT:u64 = 106;
/// @brief defines the guest_tr_limit register
const BF_REG_T_GUEST_TR_LIMIT:u64 = 107;
/// @brief defines the guest_gdtr_limit register
const BF_REG_T_GUEST_GDTR_LIMIT:u64 = 108;
/// @brief defines the guest_idtr_limit register
const BF_REG_T_GUEST_IDTR_LIMIT:u64 = 109;
/// @brief defines the guest_es_access_rights register
const BF_REG_T_GUEST_ES_ACCESS_RIGHTS:u64 = 110;
/// @brief defines the guest_cs_access_rights register
const BF_REG_T_GUEST_CS_ACCESS_RIGHTS:u64 = 111;
/// @brief defines the guest_ss_access_rights register
const BF_REG_T_GUEST_SS_ACCESS_RIGHTS:u64 = 112;
/// @brief defines the guest_ds_access_rights register
const BF_REG_T_GUEST_DS_ACCESS_RIGHTS:u64 = 113;
/// @brief defines the guest_fs_access_rights register
const BF_REG_T_GUEST_FS_ACCESS_RIGHTS:u64 = 114;
/// @brief defines the guest_gs_access_rights register
const BF_REG_T_GUEST_GS_ACCESS_RIGHTS:u64 = 115;
/// @brief defines the guest_ldtr_access_rights register
const BF_REG_T_GUEST_LDTR_ACCESS_RIGHTS:u64 = 116;
/// @brief defines the guest_tr_access_rights register
const BF_REG_T_GUEST_TR_ACCESS_RIGHTS:u64 = 117;
/// @brief defines the guest_interruptibility_state register
const BF_REG_T_GUEST_INTERRUPTIBILITY_STATE:u64 = 118;
/// @brief defines the guest_activity_state register
const BF_REG_T_GUEST_ACTIVITY_STATE:u64 = 119;
/// @brief defines the guest_smbase register
const BF_REG_T_GUEST_SMBASE:u64 = 120;
/// @brief defines the guest_sysenter_cs register
const BF_REG_T_GUEST_SYSENTER_CS:u64 = 121;
/// @brief defines the vmx_preemption_timer_value register
const BF_REG_T_VMX_PREEMPTION_TIMER_VALUE:u64 = 122;
/// @brief defines the cr0_guest_host_mask register
const BF_REG_T_CR0_GUEST_HOST_MASK:u64 = 123;
/// @brief defines the cr4_guest_host_mask register
const BF_REG_T_CR4_GUEST_HOST_MASK:u64 = 124;
/// @brief defines the cr0_read_shadow register
const BF_REG_T_CR0_READ_SHADOW:u64 = 125;
/// @brief defines the cr4_read_shadow register
const BF_REG_T_CR4_READ_SHADOW:u64 = 126;
/// @brief defines the cr3_target_value0 register
const BF_REG_T_CR3_TARGET_VALUE0:u64 = 127;
/// @brief defines the cr3_target_value1 register
const BF_REG_T_CR3_TARGET_VALUE1:u64 = 128;
/// @brief defines the cr3_target_value2 register
const BF_REG_T_CR3_TARGET_VALUE2:u64 = 129;
/// @brief defines the cr3_target_value3 register
const BF_REG_T_CR3_TARGET_VALUE3:u64 = 130;
/// @brief defines the exit_qualification register
const BF_REG_T_EXIT_QUALIFICATION:u64 = 131;
/// @brief defines the io_rcx register
const BF_REG_T_IO_RCX:u64 = 132;
/// @brief defines the io_rsi register
const BF_REG_T_IO_RSI:u64 = 133;
/// @brief defines the io_rdi register
const BF_REG_T_IO_RDI:u64 = 134;
/// @brief defines the io_rip register
const BF_REG_T_IO_RIP:u64 = 135;
/// @brief defines the guest_linear_address register
const BF_REG_T_GUEST_LINEAR_ADDRESS:u64 = 136;
/// @brief defines the guest_cr0 register
const BF_REG_T_GUEST_CR0:u64 = 137;
/// @brief defines the guest_cr3 register
const BF_REG_T_GUEST_CR3:u64 = 138;
/// @brief defines the guest_cr4 register
const BF_REG_T_GUEST_CR4:u64 = 139;
/// @brief defines the guest_es_base register
const BF_REG_T_GUEST_ES_BASE:u64 = 140;
/// @brief defines the guest_cs_base register
const BF_REG_T_GUEST_CS_BASE:u64 = 141;
/// @brief defines the guest_ss_base register
const BF_REG_T_GUEST_SS_BASE:u64 = 142;
/// @brief defines the guest_ds_base register
const BF_REG_T_GUEST_DS_BASE:u64 = 143;
/// @brief defines the guest_fs_base register
const BF_REG_T_GUEST_FS_BASE:u64 = 144;
/// @brief defines the guest_gs_base register
const BF_REG_T_GUEST_GS_BASE:u64 = 145;
/// @brief defines the guest_ldtr_base register
const BF_REG_T_GUEST_LDTR_BASE:u64 = 146;
/// @brief defines the guest_tr_base register
const BF_REG_T_GUEST_TR_BASE:u64 = 147;
/// @brief defines the guest_gdtr_base register
const BF_REG_T_GUEST_GDTR_BASE:u64 = 148;
/// @brief defines the guest_idtr_base register
const BF_REG_T_GUEST_IDTR_BASE:u64 = 149;
/// @brief defines the guest_dr7 register
const BF_REG_T_GUEST_DR7:u64 = 150;
/// @brief defines the guest_rsp register
const BF_REG_T_GUEST_RSP:u64 = 151;
/// @brief defines the guest_rip register
const BF_REG_T_GUEST_RIP:u64 = 152;
/// @brief defines the guest_rflags register
const BF_REG_T_GUEST_RFLAGS:u64 = 153;
/// @brief defines the guest_pending_debug_exceptions register
const BF_REG_T_GUEST_PENDING_DEBUG_EXCEPTIONS:u64 = 154;
/// @brief defines the guest_sysenter_esp register
const BF_REG_T_GUEST_SYSENTER_ESP:u64 = 155;
/// @brief defines the guest_sysenter_eip register
const BF_REG_T_GUEST_SYSENTER_EIP:u64 = 156;
