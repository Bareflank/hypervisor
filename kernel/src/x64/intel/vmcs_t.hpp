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

#ifndef VMCS_HPP
#define VMCS_HPP

#pragma pack(push, 1)

#include <bsl/convert.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/details/carray.hpp>
#include <bsl/safe_integral.hpp>

namespace mk
{
    namespace details
    {
        /// @brief the size of reserved field
        constexpr bsl::safe_uintmax RESERVED_SIZE{bsl::to_umax(0xFFC)};
    }

    /// @brief defines an unusable segment descriptor
    constexpr bsl::safe_uint32 VMCS_UNUSABLE_SEGMENT{bsl::to_u32(0x10000)};

    /// @brief encoding for: virtual_processor_identifier
    constexpr bsl::safe_uintmax VMCS_VIRTUAL_PROCESSOR_IDENTIFIER{bsl::to_umax(0x0000U)};
    /// @brief encoding for: posted_interrupt_notification_vector
    constexpr bsl::safe_uintmax VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR{bsl::to_umax(0x0002U)};
    /// @brief encoding for: eptp_index
    constexpr bsl::safe_uintmax VMCS_EPTP_INDEX{bsl::to_umax(0x0004U)};

    /// @brief encoding for: guest_es_selector
    constexpr bsl::safe_uintmax VMCS_GUEST_ES_SELECTOR{bsl::to_umax(0x0800U)};
    /// @brief encoding for: guest_cs_selector
    constexpr bsl::safe_uintmax VMCS_GUEST_CS_SELECTOR{bsl::to_umax(0x0802U)};
    /// @brief encoding for: guest_ss_selector
    constexpr bsl::safe_uintmax VMCS_GUEST_SS_SELECTOR{bsl::to_umax(0x0804U)};
    /// @brief encoding for: guest_ds_selector
    constexpr bsl::safe_uintmax VMCS_GUEST_DS_SELECTOR{bsl::to_umax(0x0806U)};
    /// @brief encoding for: guest_fs_selector
    constexpr bsl::safe_uintmax VMCS_GUEST_FS_SELECTOR{bsl::to_umax(0x0808U)};
    /// @brief encoding for: guest_gs_selector
    constexpr bsl::safe_uintmax VMCS_GUEST_GS_SELECTOR{bsl::to_umax(0x080AU)};
    /// @brief encoding for: guest_ldtr_selector
    constexpr bsl::safe_uintmax VMCS_GUEST_LDTR_SELECTOR{bsl::to_umax(0x080CU)};
    /// @brief encoding for: guest_tr_selector
    constexpr bsl::safe_uintmax VMCS_GUEST_TR_SELECTOR{bsl::to_umax(0x080EU)};
    /// @brief encoding for: guest_interrupt_status
    constexpr bsl::safe_uintmax VMCS_GUEST_INTERRUPT_STATUS{bsl::to_umax(0x0810U)};
    /// @brief encoding for: pml_index
    constexpr bsl::safe_uintmax VMCS_PML_INDEX{bsl::to_umax(0x0812U)};

    /// @brief encoding for: host_es_selector
    constexpr bsl::safe_uintmax VMCS_HOST_ES_SELECTOR{bsl::to_umax(0x0C00U)};
    /// @brief encoding for: host_cs_selector
    constexpr bsl::safe_uintmax VMCS_HOST_CS_SELECTOR{bsl::to_umax(0x0C02U)};
    /// @brief encoding for: host_ss_selector
    constexpr bsl::safe_uintmax VMCS_HOST_SS_SELECTOR{bsl::to_umax(0x0C04U)};
    /// @brief encoding for: host_ds_selector
    constexpr bsl::safe_uintmax VMCS_HOST_DS_SELECTOR{bsl::to_umax(0x0C06U)};
    /// @brief encoding for: host_fs_selector
    constexpr bsl::safe_uintmax VMCS_HOST_FS_SELECTOR{bsl::to_umax(0x0C08U)};
    /// @brief encoding for: host_gs_selector
    constexpr bsl::safe_uintmax VMCS_HOST_GS_SELECTOR{bsl::to_umax(0x0C0AU)};
    /// @brief encoding for: host_tr_selector
    constexpr bsl::safe_uintmax VMCS_HOST_TR_SELECTOR{bsl::to_umax(0x0C0CU)};

    /// @brief encoding for: address_of_io_bitmap_a
    constexpr bsl::safe_uintmax VMCS_ADDRESS_OF_IO_BITMAP_A{bsl::to_umax(0x2000U)};
    /// @brief encoding for: address_of_io_bitmap_b
    constexpr bsl::safe_uintmax VMCS_ADDRESS_OF_IO_BITMAP_B{bsl::to_umax(0x2002U)};
    /// @brief encoding for: address_of_msr_bitmaps
    constexpr bsl::safe_uintmax VMCS_ADDRESS_OF_MSR_BITMAPS{bsl::to_umax(0x2004U)};
    /// @brief encoding for: vmexit_msr_store_address
    constexpr bsl::safe_uintmax VMCS_VMEXIT_MSR_STORE_ADDRESS{bsl::to_umax(0x2006U)};
    /// @brief encoding for: vmexit_msr_load_address
    constexpr bsl::safe_uintmax VMCS_VMEXIT_MSR_LOAD_ADDRESS{bsl::to_umax(0x2008U)};
    /// @brief encoding for: vmentry_msr_load_address
    constexpr bsl::safe_uintmax VMCS_VMENTRY_MSR_LOAD_ADDRESS{bsl::to_umax(0x200AU)};
    /// @brief encoding for: executive_vmcs_pointer
    constexpr bsl::safe_uintmax VMCS_EXECUTIVE_VMCS_POINTER{bsl::to_umax(0x200CU)};
    /// @brief encoding for: pml_address
    constexpr bsl::safe_uintmax VMCS_PML_ADDRESS{bsl::to_umax(0x200EU)};
    /// @brief encoding for: tsc_offset
    constexpr bsl::safe_uintmax VMCS_TSC_OFFSET{bsl::to_umax(0x2010U)};
    /// @brief encoding for: virtual_apic_address
    constexpr bsl::safe_uintmax VMCS_VIRTUAL_APIC_ADDRESS{bsl::to_umax(0x2012U)};
    /// @brief encoding for: apic_access_address
    constexpr bsl::safe_uintmax VMCS_APIC_ACCESS_ADDRESS{bsl::to_umax(0x2014U)};
    /// @brief encoding for: posted_interrupt_descriptor_address
    constexpr bsl::safe_uintmax VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS{bsl::to_umax(0x2016U)};
    /// @brief encoding for: vm_function_controls
    constexpr bsl::safe_uintmax VMCS_VM_FUNCTION_CONTROLS{bsl::to_umax(0x2018U)};
    /// @brief encoding for: ept_pointer
    constexpr bsl::safe_uintmax VMCS_EPT_POINTER{bsl::to_umax(0x201AU)};
    /// @brief encoding for: eoi_exit_bitmap0
    constexpr bsl::safe_uintmax VMCS_EOI_EXIT_BITMAP0{bsl::to_umax(0x201CU)};
    /// @brief encoding for: eoi_exit_bitmap1
    constexpr bsl::safe_uintmax VMCS_EOI_EXIT_BITMAP1{bsl::to_umax(0x201EU)};
    /// @brief encoding for: eoi_exit_bitmap2
    constexpr bsl::safe_uintmax VMCS_EOI_EXIT_BITMAP2{bsl::to_umax(0x2020U)};
    /// @brief encoding for: eoi_exit_bitmap3
    constexpr bsl::safe_uintmax VMCS_EOI_EXIT_BITMAP3{bsl::to_umax(0x2022U)};
    /// @brief encoding for: eptp_list_address
    constexpr bsl::safe_uintmax VMCS_EPTP_LIST_ADDRESS{bsl::to_umax(0x2024U)};
    /// @brief encoding for: vmread_bitmap_address
    constexpr bsl::safe_uintmax VMCS_VMREAD_BITMAP_ADDRESS{bsl::to_umax(0x2026U)};
    /// @brief encoding for: vmwrite_bitmap_address
    constexpr bsl::safe_uintmax VMCS_VMWRITE_BITMAP_ADDRESS{bsl::to_umax(0x2028U)};
    /// @brief encoding for: virt_exception_information_address
    constexpr bsl::safe_uintmax VMCS_VIRT_EXCEPTION_INFORMATION_ADDRESS{bsl::to_umax(0x202AU)};
    /// @brief encoding for: xss_exiting_bitmap
    constexpr bsl::safe_uintmax VMCS_XSS_EXITING_BITMAP{bsl::to_umax(0x202CU)};
    /// @brief encoding for: encls_exiting_bitmap
    constexpr bsl::safe_uintmax VMCS_ENCLS_EXITING_BITMAP{bsl::to_umax(0x202EU)};
    /// @brief encoding for: sub_page_permission_table_pointer
    constexpr bsl::safe_uintmax VMCS_SUB_PAGE_PERMISSION_TABLE_POINTER{bsl::to_umax(0x2030U)};
    /// @brief encoding for: tls_multiplier
    constexpr bsl::safe_uintmax VMCS_TLS_MULTIPLIER{bsl::to_umax(0x2032U)};

    /// @brief encoding for: guest_physical_address
    constexpr bsl::safe_uintmax VMCS_GUEST_PHYSICAL_ADDRESS{bsl::to_umax(0x2400U)};

    /// @brief encoding for: vmcs_link_pointer
    constexpr bsl::safe_uintmax VMCS_VMCS_LINK_POINTER{bsl::to_umax(0x2800U)};
    /// @brief encoding for: guest_ia32_debugctl
    constexpr bsl::safe_uintmax VMCS_GUEST_IA32_DEBUGCTL{bsl::to_umax(0x2802U)};
    /// @brief encoding for: guest_ia32_pat
    constexpr bsl::safe_uintmax VMCS_GUEST_IA32_PAT{bsl::to_umax(0x2804U)};
    /// @brief encoding for: guest_ia32_efer
    constexpr bsl::safe_uintmax VMCS_GUEST_IA32_EFER{bsl::to_umax(0x2806U)};
    /// @brief encoding for: guest_ia32_perf_global_ctrl
    constexpr bsl::safe_uintmax VMCS_GUEST_IA32_PERF_GLOBAL_CTRL{bsl::to_umax(0x2808U)};
    /// @brief encoding for: guest_pdpte0
    constexpr bsl::safe_uintmax VMCS_GUEST_PDPTE0{bsl::to_umax(0x280AU)};
    /// @brief encoding for: guest_pdpte1
    constexpr bsl::safe_uintmax VMCS_GUEST_PDPTE1{bsl::to_umax(0x280CU)};
    /// @brief encoding for: guest_pdpte2
    constexpr bsl::safe_uintmax VMCS_GUEST_PDPTE2{bsl::to_umax(0x280EU)};
    /// @brief encoding for: guest_pdpte3
    constexpr bsl::safe_uintmax VMCS_GUEST_PDPTE3{bsl::to_umax(0x2810U)};
    /// @brief encoding for: guest_ia32_bndcfgs
    constexpr bsl::safe_uintmax VMCS_GUEST_IA32_BNDCFGS{bsl::to_umax(0x2812U)};
    /// @brief encoding for: guest_rtit_ctl
    constexpr bsl::safe_uintmax VMCS_GUEST_RTIT_CTL{bsl::to_umax(0x2814U)};

    /// @brief encoding for: host_ia32_pat
    constexpr bsl::safe_uintmax VMCS_HOST_IA32_PAT{bsl::to_umax(0x2C00U)};
    /// @brief encoding for: host_ia32_efer
    constexpr bsl::safe_uintmax VMCS_HOST_IA32_EFER{bsl::to_umax(0x2C02U)};
    /// @brief encoding for: host_ia32_perf_global_ctrl
    constexpr bsl::safe_uintmax VMCS_HOST_IA32_PERF_GLOBAL_CTRL{bsl::to_umax(0x2C04U)};

    /// @brief encoding for: pin_based_vm_execution_ctls
    constexpr bsl::safe_uintmax VMCS_PIN_BASED_VM_EXECUTION_CTLS{bsl::to_umax(0x4000U)};
    /// @brief encoding for: primary_proc_based_vm_execution_ctls
    constexpr bsl::safe_uintmax VMCS_PRIMARY_PROC_BASED_VM_EXECUTION_CTLS{bsl::to_umax(0x4002U)};
    /// @brief encoding for: exception_bitmap
    constexpr bsl::safe_uintmax VMCS_EXCEPTION_BITMAP{bsl::to_umax(0x4004U)};
    /// @brief encoding for: page_fault_error_code_mask
    constexpr bsl::safe_uintmax VMCS_PAGE_FAULT_ERROR_CODE_MASK{bsl::to_umax(0x4006U)};
    /// @brief encoding for: page_fault_error_code_match
    constexpr bsl::safe_uintmax VMCS_PAGE_FAULT_ERROR_CODE_MATCH{bsl::to_umax(0x4008U)};
    /// @brief encoding for: cr3_target_count
    constexpr bsl::safe_uintmax VMCS_CR3_TARGET_COUNT{bsl::to_umax(0x400AU)};
    /// @brief encoding for: vmexit_ctls
    constexpr bsl::safe_uintmax VMCS_VMEXIT_CTLS{bsl::to_umax(0x400CU)};
    /// @brief encoding for: vmexit_msr_store_count
    constexpr bsl::safe_uintmax VMCS_VMEXIT_MSR_STORE_COUNT{bsl::to_umax(0x400EU)};
    /// @brief encoding for: vmexit_msr_load_count
    constexpr bsl::safe_uintmax VMCS_VMEXIT_MSR_LOAD_COUNT{bsl::to_umax(0x4010U)};
    /// @brief encoding for: vmentry_ctls
    constexpr bsl::safe_uintmax VMCS_VMENTRY_CTLS{bsl::to_umax(0x4012U)};
    /// @brief encoding for: vmentry_msr_load_count
    constexpr bsl::safe_uintmax VMCS_VMENTRY_MSR_LOAD_COUNT{bsl::to_umax(0x4014U)};
    /// @brief encoding for: vmentry_interrupt_information_field
    constexpr bsl::safe_uintmax VMCS_VMENTRY_INTERRUPT_INFORMATION_FIELD{bsl::to_umax(0x4016U)};
    /// @brief encoding for: vmentry_exception_error_code
    constexpr bsl::safe_uintmax VMCS_VMENTRY_EXCEPTION_ERROR_CODE{bsl::to_umax(0x4018U)};
    /// @brief encoding for: vmentry_instruction_length
    constexpr bsl::safe_uintmax VMCS_VMENTRY_INSTRUCTION_LENGTH{bsl::to_umax(0x401AU)};
    /// @brief encoding for: tpr_threshold
    constexpr bsl::safe_uintmax VMCS_TPR_THRESHOLD{bsl::to_umax(0x401CU)};
    /// @brief encoding for: secondary_proc_based_vm_execution_ctls
    constexpr bsl::safe_uintmax VMCS_SECONDARY_PROC_BASED_VM_EXECUTION_CTLS{bsl::to_umax(0x401EU)};
    /// @brief encoding for: ple_gap
    constexpr bsl::safe_uintmax VMCS_PLE_GAP{bsl::to_umax(0x4020U)};
    /// @brief encoding for: ple_window
    constexpr bsl::safe_uintmax VMCS_PLE_WINDOW{bsl::to_umax(0x4022U)};

    /// @brief encoding for: vm_instruction_error
    constexpr bsl::safe_uintmax VMCS_VM_INSTRUCTION_ERROR{bsl::to_umax(0x4400U)};
    /// @brief encoding for: exit_reason
    constexpr bsl::safe_uintmax VMCS_EXIT_REASON{bsl::to_umax(0x4402U)};
    /// @brief encoding for: vmexit_interruption_information
    constexpr bsl::safe_uintmax VMCS_VMEXIT_INTERRUPTION_INFORMATION{bsl::to_umax(0x4404U)};
    /// @brief encoding for: vmexit_interruption_error_code
    constexpr bsl::safe_uintmax VMCS_VMEXIT_INTERRUPTION_ERROR_CODE{bsl::to_umax(0x4406U)};
    /// @brief encoding for: idt_vectoring_information_field
    constexpr bsl::safe_uintmax VMCS_IDT_VECTORING_INFORMATION_FIELD{bsl::to_umax(0x4408U)};
    /// @brief encoding for: idt_vectoring_error_code
    constexpr bsl::safe_uintmax VMCS_IDT_VECTORING_ERROR_CODE{bsl::to_umax(0x440AU)};
    /// @brief encoding for: vmexit_instruction_length
    constexpr bsl::safe_uintmax VMCS_VMEXIT_INSTRUCTION_LENGTH{bsl::to_umax(0x440CU)};
    /// @brief encoding for: vmexit_instruction_information
    constexpr bsl::safe_uintmax VMCS_VMEXIT_INSTRUCTION_INFORMATION{bsl::to_umax(0x440EU)};

    /// @brief encoding for: guest_es_limit
    constexpr bsl::safe_uintmax VMCS_GUEST_ES_LIMIT{bsl::to_umax(0x4800U)};
    /// @brief encoding for: guest_cs_limit
    constexpr bsl::safe_uintmax VMCS_GUEST_CS_LIMIT{bsl::to_umax(0x4802U)};
    /// @brief encoding for: guest_ss_limit
    constexpr bsl::safe_uintmax VMCS_GUEST_SS_LIMIT{bsl::to_umax(0x4804U)};
    /// @brief encoding for: guest_ds_limit
    constexpr bsl::safe_uintmax VMCS_GUEST_DS_LIMIT{bsl::to_umax(0x4806U)};
    /// @brief encoding for: guest_fs_limit
    constexpr bsl::safe_uintmax VMCS_GUEST_FS_LIMIT{bsl::to_umax(0x4808U)};
    /// @brief encoding for: guest_gs_limit
    constexpr bsl::safe_uintmax VMCS_GUEST_GS_LIMIT{bsl::to_umax(0x480AU)};
    /// @brief encoding for: guest_ldtr_limit
    constexpr bsl::safe_uintmax VMCS_GUEST_LDTR_LIMIT{bsl::to_umax(0x480CU)};
    /// @brief encoding for: guest_tr_limit
    constexpr bsl::safe_uintmax VMCS_GUEST_TR_LIMIT{bsl::to_umax(0x480EU)};
    /// @brief encoding for: guest_gdtr_limit
    constexpr bsl::safe_uintmax VMCS_GUEST_GDTR_LIMIT{bsl::to_umax(0x4810U)};
    /// @brief encoding for: guest_idtr_limit
    constexpr bsl::safe_uintmax VMCS_GUEST_IDTR_LIMIT{bsl::to_umax(0x4812U)};
    /// @brief encoding for: guest_es_access_rights
    constexpr bsl::safe_uintmax VMCS_GUEST_ES_ACCESS_RIGHTS{bsl::to_umax(0x4814U)};
    /// @brief encoding for: guest_cs_access_rights
    constexpr bsl::safe_uintmax VMCS_GUEST_CS_ACCESS_RIGHTS{bsl::to_umax(0x4816U)};
    /// @brief encoding for: guest_ss_access_rights
    constexpr bsl::safe_uintmax VMCS_GUEST_SS_ACCESS_RIGHTS{bsl::to_umax(0x4818U)};
    /// @brief encoding for: guest_ds_access_rights
    constexpr bsl::safe_uintmax VMCS_GUEST_DS_ACCESS_RIGHTS{bsl::to_umax(0x481AU)};
    /// @brief encoding for: guest_fs_access_rights
    constexpr bsl::safe_uintmax VMCS_GUEST_FS_ACCESS_RIGHTS{bsl::to_umax(0x481CU)};
    /// @brief encoding for: guest_gs_access_rights
    constexpr bsl::safe_uintmax VMCS_GUEST_GS_ACCESS_RIGHTS{bsl::to_umax(0x481EU)};
    /// @brief encoding for: guest_ldtr_access_rights
    constexpr bsl::safe_uintmax VMCS_GUEST_LDTR_ACCESS_RIGHTS{bsl::to_umax(0x4820U)};
    /// @brief encoding for: guest_tr_access_rights
    constexpr bsl::safe_uintmax VMCS_GUEST_TR_ACCESS_RIGHTS{bsl::to_umax(0x4822U)};
    /// @brief encoding for: guest_interruptibility_state
    constexpr bsl::safe_uintmax VMCS_GUEST_INTERRUPTIBILITY_STATE{bsl::to_umax(0x4824U)};
    /// @brief encoding for: guest_activity_state
    constexpr bsl::safe_uintmax VMCS_GUEST_ACTIVITY_STATE{bsl::to_umax(0x4826U)};
    /// @brief encoding for: guest_smbase
    constexpr bsl::safe_uintmax VMCS_GUEST_SMBASE{bsl::to_umax(0x4828U)};
    /// @brief encoding for: guest_ia32_sysenter_cs
    constexpr bsl::safe_uintmax VMCS_GUEST_IA32_SYSENTER_CS{bsl::to_umax(0x482AU)};
    /// @brief encoding for: vmx_preemption_timer_value
    constexpr bsl::safe_uintmax VMCS_VMX_PREEMPTION_TIMER_VALUE{bsl::to_umax(0x482EU)};

    /// @brief encoding for: host_ia32_sysenter_cs
    constexpr bsl::safe_uintmax VMCS_HOST_IA32_SYSENTER_CS{bsl::to_umax(0x4C00U)};

    /// @brief encoding for: cr0_guest_host_mask
    constexpr bsl::safe_uintmax VMCS_CR0_GUEST_HOST_MASK{bsl::to_umax(0x6000U)};
    /// @brief encoding for: cr4_guest_host_mask
    constexpr bsl::safe_uintmax VMCS_CR4_GUEST_HOST_MASK{bsl::to_umax(0x6002U)};
    /// @brief encoding for: cr0_read_shadow
    constexpr bsl::safe_uintmax VMCS_CR0_READ_SHADOW{bsl::to_umax(0x6004U)};
    /// @brief encoding for: cr4_read_shadow
    constexpr bsl::safe_uintmax VMCS_CR4_READ_SHADOW{bsl::to_umax(0x6006U)};
    /// @brief encoding for: cr3_target_value0
    constexpr bsl::safe_uintmax VMCS_CR3_TARGET_VALUE0{bsl::to_umax(0x6008U)};
    /// @brief encoding for: cr3_target_value1
    constexpr bsl::safe_uintmax VMCS_CR3_TARGET_VALUE1{bsl::to_umax(0x600AU)};
    /// @brief encoding for: cr3_target_value2
    constexpr bsl::safe_uintmax VMCS_CR3_TARGET_VALUE2{bsl::to_umax(0x600CU)};
    /// @brief encoding for: cr3_target_value3
    constexpr bsl::safe_uintmax VMCS_CR3_TARGET_VALUE3{bsl::to_umax(0x600EU)};

    /// @brief encoding for: exit_qualification
    constexpr bsl::safe_uintmax VMCS_EXIT_QUALIFICATION{bsl::to_umax(0x6400U)};
    /// @brief encoding for: io_rcx
    constexpr bsl::safe_uintmax VMCS_IO_RCX{bsl::to_umax(0x6402U)};
    /// @brief encoding for: io_rsi
    constexpr bsl::safe_uintmax VMCS_IO_RSI{bsl::to_umax(0x6404U)};
    /// @brief encoding for: io_rdi
    constexpr bsl::safe_uintmax VMCS_IO_RDI{bsl::to_umax(0x6406U)};
    /// @brief encoding for: io_rip
    constexpr bsl::safe_uintmax VMCS_IO_RIP{bsl::to_umax(0x6408U)};
    /// @brief encoding for: guest_linear_address
    constexpr bsl::safe_uintmax VMCS_GUEST_LINEAR_ADDRESS{bsl::to_umax(0x640AU)};

    /// @brief encoding for: guest_cr0
    constexpr bsl::safe_uintmax VMCS_GUEST_CR0{bsl::to_umax(0x6800U)};
    /// @brief encoding for: guest_cr3
    constexpr bsl::safe_uintmax VMCS_GUEST_CR3{bsl::to_umax(0x6802U)};
    /// @brief encoding for: guest_cr4
    constexpr bsl::safe_uintmax VMCS_GUEST_CR4{bsl::to_umax(0x6804U)};
    /// @brief encoding for: guest_es_base
    constexpr bsl::safe_uintmax VMCS_GUEST_ES_BASE{bsl::to_umax(0x6806U)};
    /// @brief encoding for: guest_cs_base
    constexpr bsl::safe_uintmax VMCS_GUEST_CS_BASE{bsl::to_umax(0x6808U)};
    /// @brief encoding for: guest_ss_base
    constexpr bsl::safe_uintmax VMCS_GUEST_SS_BASE{bsl::to_umax(0x680AU)};
    /// @brief encoding for: guest_ds_base
    constexpr bsl::safe_uintmax VMCS_GUEST_DS_BASE{bsl::to_umax(0x680CU)};
    /// @brief encoding for: guest_fs_base
    constexpr bsl::safe_uintmax VMCS_GUEST_FS_BASE{bsl::to_umax(0x680EU)};
    /// @brief encoding for: guest_gs_base
    constexpr bsl::safe_uintmax VMCS_GUEST_GS_BASE{bsl::to_umax(0x6810U)};
    /// @brief encoding for: guest_ldtr_base
    constexpr bsl::safe_uintmax VMCS_GUEST_LDTR_BASE{bsl::to_umax(0x6812U)};
    /// @brief encoding for: guest_tr_base
    constexpr bsl::safe_uintmax VMCS_GUEST_TR_BASE{bsl::to_umax(0x6814U)};
    /// @brief encoding for: guest_gdtr_base
    constexpr bsl::safe_uintmax VMCS_GUEST_GDTR_BASE{bsl::to_umax(0x6816U)};
    /// @brief encoding for: guest_idtr_base
    constexpr bsl::safe_uintmax VMCS_GUEST_IDTR_BASE{bsl::to_umax(0x6818U)};
    /// @brief encoding for: guest_dr7
    constexpr bsl::safe_uintmax VMCS_GUEST_DR7{bsl::to_umax(0x681AU)};
    /// @brief encoding for: guest_rsp
    constexpr bsl::safe_uintmax VMCS_GUEST_RSP{bsl::to_umax(0x681CU)};
    /// @brief encoding for: guest_rip
    constexpr bsl::safe_uintmax VMCS_GUEST_RIP{bsl::to_umax(0x681EU)};
    /// @brief encoding for: guest_rflags
    constexpr bsl::safe_uintmax VMCS_GUEST_RFLAGS{bsl::to_umax(0x6820U)};
    /// @brief encoding for: guest_pending_debug_exceptions
    constexpr bsl::safe_uintmax VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS{bsl::to_umax(0x6822U)};
    /// @brief encoding for: guest_ia32_sysenter_esp
    constexpr bsl::safe_uintmax VMCS_GUEST_IA32_SYSENTER_ESP{bsl::to_umax(0x6824U)};
    /// @brief encoding for: guest_ia32_sysenter_eip
    constexpr bsl::safe_uintmax VMCS_GUEST_IA32_SYSENTER_EIP{bsl::to_umax(0x6826U)};

    /// @brief encoding for: host_cr0
    constexpr bsl::safe_uintmax VMCS_HOST_CR0{bsl::to_umax(0x6C00U)};
    /// @brief encoding for: host_cr3
    constexpr bsl::safe_uintmax VMCS_HOST_CR3{bsl::to_umax(0x6C02U)};
    /// @brief encoding for: host_cr4
    constexpr bsl::safe_uintmax VMCS_HOST_CR4{bsl::to_umax(0x6C04U)};
    /// @brief encoding for: host_fs_base
    constexpr bsl::safe_uintmax VMCS_HOST_FS_BASE{bsl::to_umax(0x6C06U)};
    /// @brief encoding for: host_gs_base
    constexpr bsl::safe_uintmax VMCS_HOST_GS_BASE{bsl::to_umax(0x6C08U)};
    /// @brief encoding for: host_tr_baseD
    constexpr bsl::safe_uintmax VMCS_HOST_TR_BASE{bsl::to_umax(0x6C0AU)};
    /// @brief encoding for: host_gdtr_base
    constexpr bsl::safe_uintmax VMCS_HOST_GDTR_BASE{bsl::to_umax(0x6C0CU)};
    /// @brief encoding for: host_idtr_base
    constexpr bsl::safe_uintmax VMCS_HOST_IDTR_BASE{bsl::to_umax(0x6C0EU)};
    /// @brief encoding for: host_ia32_sysenter_esp
    constexpr bsl::safe_uintmax VMCS_HOST_IA32_SYSENTER_ESP{bsl::to_umax(0x6C10U)};
    /// @brief encoding for: host_ia32_sysenter_eip
    constexpr bsl::safe_uintmax VMCS_HOST_IA32_SYSENTER_EIP{bsl::to_umax(0x6C12U)};
    /// @brief encoding for: host_rsp
    constexpr bsl::safe_uintmax VMCS_HOST_RSP{bsl::to_umax(0x6C14U)};
    /// @brief encoding for: host_rip
    constexpr bsl::safe_uintmax VMCS_HOST_RIP{bsl::to_umax(0x6C16U)};

    /// @struct mk::vmcs_t
    ///
    /// <!-- description -->
    ///   @brief The following defines the structure of the VMCS used by
    ///     Intel's hypervisor extensions.
    ///
    struct vmcs_t final
    {
        /// @brief defines the revision ID
        bsl::uint32 revision_id;

        /// @brief reserved
        bsl::details::carray<bsl::uint8, details::RESERVED_SIZE.get()> reserved;
    };

    namespace details
    {
        /// @brief defined the expected size of the pdt_t struct
        constexpr bsl::safe_uintmax EXPECTED_VMCS_T_SIZE{bsl::to_umax(HYPERVISOR_PAGE_SIZE)};

        /// Check to make sure the pdt_t is the right size.
        static_assert(sizeof(vmcs_t) == EXPECTED_VMCS_T_SIZE);
    }
}

#pragma pack(pop)

#endif
