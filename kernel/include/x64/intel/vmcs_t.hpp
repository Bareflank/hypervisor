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

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/safe_integral.hpp>

#pragma pack(push, 1)

namespace mk
{
    /// @brief the size of reserved field
    constexpr auto RESERVED_SIZE{0xFFC_umx};

    /// @brief defines an unusable segment descriptor
    constexpr auto VMCS_UNUSABLE_SEGMENT{0x10000_u32};

    /// @brief encoding for: virtual_processor_identifier
    constexpr auto VMCS_VIRTUAL_PROCESSOR_IDENTIFIER{0x0000_umx};
    /// @brief encoding for: posted_interrupt_notification_vector
    constexpr auto VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR{0x0002_umx};
    /// @brief encoding for: eptp_index
    constexpr auto VMCS_EPTP_INDEX{0x0004_umx};

    /// @brief encoding for: guest_es_selector
    constexpr auto VMCS_GUEST_ES_SELECTOR{0x0800_umx};
    /// @brief encoding for: guest_cs_selector
    constexpr auto VMCS_GUEST_CS_SELECTOR{0x0802_umx};
    /// @brief encoding for: guest_ss_selector
    constexpr auto VMCS_GUEST_SS_SELECTOR{0x0804_umx};
    /// @brief encoding for: guest_ds_selector
    constexpr auto VMCS_GUEST_DS_SELECTOR{0x0806_umx};
    /// @brief encoding for: guest_fs_selector
    constexpr auto VMCS_GUEST_FS_SELECTOR{0x0808_umx};
    /// @brief encoding for: guest_gs_selector
    constexpr auto VMCS_GUEST_GS_SELECTOR{0x080A_umx};
    /// @brief encoding for: guest_ldtr_selector
    constexpr auto VMCS_GUEST_LDTR_SELECTOR{0x080C_umx};
    /// @brief encoding for: guest_tr_selector
    constexpr auto VMCS_GUEST_TR_SELECTOR{0x080E_umx};
    /// @brief encoding for: guest_interrupt_status
    constexpr auto VMCS_GUEST_INTERRUPT_STATUS{0x0810_umx};
    /// @brief encoding for: pml_index
    constexpr auto VMCS_PML_INDEX{0x0812_umx};

    /// @brief encoding for: host_es_selector
    constexpr auto VMCS_HOST_ES_SELECTOR{0x0C00_umx};
    /// @brief encoding for: host_cs_selector
    constexpr auto VMCS_HOST_CS_SELECTOR{0x0C02_umx};
    /// @brief encoding for: host_ss_selector
    constexpr auto VMCS_HOST_SS_SELECTOR{0x0C04_umx};
    /// @brief encoding for: host_ds_selector
    constexpr auto VMCS_HOST_DS_SELECTOR{0x0C06_umx};
    /// @brief encoding for: host_fs_selector
    constexpr auto VMCS_HOST_FS_SELECTOR{0x0C08_umx};
    /// @brief encoding for: host_gs_selector
    constexpr auto VMCS_HOST_GS_SELECTOR{0x0C0A_umx};
    /// @brief encoding for: host_tr_selector
    constexpr auto VMCS_HOST_TR_SELECTOR{0x0C0C_umx};

    /// @brief encoding for: address_of_io_bitmap_a
    constexpr auto VMCS_ADDRESS_OF_IO_BITMAP_A{0x2000_umx};
    /// @brief encoding for: address_of_io_bitmap_b
    constexpr auto VMCS_ADDRESS_OF_IO_BITMAP_B{0x2002_umx};
    /// @brief encoding for: address_of_msr_bitmaps
    constexpr auto VMCS_ADDRESS_OF_MSR_BITMAPS{0x2004_umx};
    /// @brief encoding for: vmexit_msr_store_address
    constexpr auto VMCS_VMEXIT_MSR_STORE_ADDRESS{0x2006_umx};
    /// @brief encoding for: vmexit_msr_load_address
    constexpr auto VMCS_VMEXIT_MSR_LOAD_ADDRESS{0x2008_umx};
    /// @brief encoding for: vmentry_msr_load_address
    constexpr auto VMCS_VMENTRY_MSR_LOAD_ADDRESS{0x200A_umx};
    /// @brief encoding for: executive_vmcs_pointer
    constexpr auto VMCS_EXECUTIVE_VMCS_POINTER{0x200C_umx};
    /// @brief encoding for: pml_address
    constexpr auto VMCS_PML_ADDRESS{0x200E_umx};
    /// @brief encoding for: tsc_offset
    constexpr auto VMCS_TSC_OFFSET{0x2010_umx};
    /// @brief encoding for: virtual_apic_address
    constexpr auto VMCS_VIRTUAL_APIC_ADDRESS{0x2012_umx};
    /// @brief encoding for: apic_access_address
    constexpr auto VMCS_APIC_ACCESS_ADDRESS{0x2014_umx};
    /// @brief encoding for: posted_interrupt_descriptor_address
    constexpr auto VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS{0x2016_umx};
    /// @brief encoding for: vm_function_controls
    constexpr auto VMCS_VM_FUNCTION_CONTROLS{0x2018_umx};
    /// @brief encoding for: ept_pointer
    constexpr auto VMCS_EPT_POINTER{0x201A_umx};
    /// @brief encoding for: eoi_exit_bitmap0
    constexpr auto VMCS_EOI_EXIT_BITMAP0{0x201C_umx};
    /// @brief encoding for: eoi_exit_bitmap1
    constexpr auto VMCS_EOI_EXIT_BITMAP1{0x201E_umx};
    /// @brief encoding for: eoi_exit_bitmap2
    constexpr auto VMCS_EOI_EXIT_BITMAP2{0x2020_umx};
    /// @brief encoding for: eoi_exit_bitmap3
    constexpr auto VMCS_EOI_EXIT_BITMAP3{0x2022_umx};
    /// @brief encoding for: eptp_list_address
    constexpr auto VMCS_EPTP_LIST_ADDRESS{0x2024_umx};
    /// @brief encoding for: vmread_bitmap_address
    constexpr auto VMCS_VMREAD_BITMAP_ADDRESS{0x2026_umx};
    /// @brief encoding for: vmwrite_bitmap_address
    constexpr auto VMCS_VMWRITE_BITMAP_ADDRESS{0x2028_umx};
    /// @brief encoding for: virt_exception_information_address
    constexpr auto VMCS_VIRT_EXCEPTION_INFORMATION_ADDRESS{0x202A_umx};
    /// @brief encoding for: xss_exiting_bitmap
    constexpr auto VMCS_XSS_EXITING_BITMAP{0x202C_umx};
    /// @brief encoding for: encls_exiting_bitmap
    constexpr auto VMCS_ENCLS_EXITING_BITMAP{0x202E_umx};
    /// @brief encoding for: sub_page_permission_table_pointer
    constexpr auto VMCS_SUB_PAGE_PERMISSION_TABLE_POINTER{0x2030_umx};
    /// @brief encoding for: tls_multiplier
    constexpr auto VMCS_TLS_MULTIPLIER{0x2032_umx};

    /// @brief encoding for: guest_physical_address
    constexpr auto VMCS_GUEST_PHYSICAL_ADDRESS{0x2400_umx};

    /// @brief encoding for: vmcs_link_pointer
    constexpr auto VMCS_VMCS_LINK_POINTER{0x2800_umx};
    /// @brief encoding for: guest_debugctl
    constexpr auto VMCS_GUEST_DEBUGCTL{0x2802_umx};
    /// @brief encoding for: guest_pat
    constexpr auto VMCS_GUEST_PAT{0x2804_umx};
    /// @brief encoding for: guest_efer
    constexpr auto VMCS_GUEST_EFER{0x2806_umx};
    /// @brief encoding for: guest_perf_global_ctrl
    constexpr auto VMCS_GUEST_PERF_GLOBAL_CTRL{0x2808_umx};
    /// @brief encoding for: guest_pdpte0
    constexpr auto VMCS_GUEST_PDPTE0{0x280A_umx};
    /// @brief encoding for: guest_pdpte1
    constexpr auto VMCS_GUEST_PDPTE1{0x280C_umx};
    /// @brief encoding for: guest_pdpte2
    constexpr auto VMCS_GUEST_PDPTE2{0x280E_umx};
    /// @brief encoding for: guest_pdpte3
    constexpr auto VMCS_GUEST_PDPTE3{0x2810_umx};
    /// @brief encoding for: guest_bndcfgs
    constexpr auto VMCS_GUEST_BNDCFGS{0x2812_umx};
    /// @brief encoding for: guest_rtit_ctl
    constexpr auto VMCS_GUEST_RTIT_CTL{0x2814_umx};

    /// @brief encoding for: host_pat
    constexpr auto VMCS_HOST_PAT{0x2C00_umx};
    /// @brief encoding for: host_efer
    constexpr auto VMCS_HOST_EFER{0x2C02_umx};
    /// @brief encoding for: host_perf_global_ctrl
    constexpr auto VMCS_HOST_PERF_GLOBAL_CTRL{0x2C04_umx};

    /// @brief encoding for: pin_based_vm_execution_ctls
    constexpr auto VMCS_PIN_BASED_VM_EXECUTION_CTLS{0x4000_umx};
    /// @brief encoding for: primary_proc_based_vm_execution_ctls
    constexpr auto VMCS_PRIMARY_PROC_BASED_VM_EXECUTION_CTLS{0x4002_umx};
    /// @brief encoding for: exception_bitmap
    constexpr auto VMCS_EXCEPTION_BITMAP{0x4004_umx};
    /// @brief encoding for: page_fault_error_code_mask
    constexpr auto VMCS_PAGE_FAULT_ERROR_CODE_MASK{0x4006_umx};
    /// @brief encoding for: page_fault_error_code_match
    constexpr auto VMCS_PAGE_FAULT_ERROR_CODE_MATCH{0x4008_umx};
    /// @brief encoding for: cr3_target_count
    constexpr auto VMCS_CR3_TARGET_COUNT{0x400A_umx};
    /// @brief encoding for: vmexit_ctls
    constexpr auto VMCS_VMEXIT_CTLS{0x400C_umx};
    /// @brief encoding for: vmexit_msr_store_count
    constexpr auto VMCS_VMEXIT_MSR_STORE_COUNT{0x400E_umx};
    /// @brief encoding for: vmexit_msr_load_count
    constexpr auto VMCS_VMEXIT_MSR_LOAD_COUNT{0x4010_umx};
    /// @brief encoding for: vmentry_ctls
    constexpr auto VMCS_VMENTRY_CTLS{0x4012_umx};
    /// @brief encoding for: vmentry_msr_load_count
    constexpr auto VMCS_VMENTRY_MSR_LOAD_COUNT{0x4014_umx};
    /// @brief encoding for: vmentry_interrupt_information_field
    constexpr auto VMCS_VMENTRY_INTERRUPT_INFORMATION_FIELD{0x4016_umx};
    /// @brief encoding for: vmentry_exception_error_code
    constexpr auto VMCS_VMENTRY_EXCEPTION_ERROR_CODE{0x4018_umx};
    /// @brief encoding for: vmentry_instruction_length
    constexpr auto VMCS_VMENTRY_INSTRUCTION_LENGTH{0x401A_umx};
    /// @brief encoding for: tpr_threshold
    constexpr auto VMCS_TPR_THRESHOLD{0x401C_umx};
    /// @brief encoding for: secondary_proc_based_vm_execution_ctls
    constexpr auto VMCS_SECONDARY_PROC_BASED_VM_EXECUTION_CTLS{0x401E_umx};
    /// @brief encoding for: ple_gap
    constexpr auto VMCS_PLE_GAP{0x4020_umx};
    /// @brief encoding for: ple_window
    constexpr auto VMCS_PLE_WINDOW{0x4022_umx};

    /// @brief encoding for: vm_instruction_error
    constexpr auto VMCS_VM_INSTRUCTION_ERROR{0x4400_umx};
    /// @brief encoding for: exit_reason
    constexpr auto VMCS_EXIT_REASON{0x4402_umx};
    /// @brief encoding for: vmexit_interruption_information
    constexpr auto VMCS_VMEXIT_INTERRUPTION_INFORMATION{0x4404_umx};
    /// @brief encoding for: vmexit_interruption_error_code
    constexpr auto VMCS_VMEXIT_INTERRUPTION_ERROR_CODE{0x4406_umx};
    /// @brief encoding for: idt_vectoring_information_field
    constexpr auto VMCS_IDT_VECTORING_INFORMATION_FIELD{0x4408_umx};
    /// @brief encoding for: idt_vectoring_error_code
    constexpr auto VMCS_IDT_VECTORING_ERROR_CODE{0x440A_umx};
    /// @brief encoding for: vmexit_instruction_length
    constexpr auto VMCS_VMEXIT_INSTRUCTION_LENGTH{0x440C_umx};
    /// @brief encoding for: vmexit_instruction_information
    constexpr auto VMCS_VMEXIT_INSTRUCTION_INFORMATION{0x440E_umx};

    /// @brief encoding for: guest_es_limit
    constexpr auto VMCS_GUEST_ES_LIMIT{0x4800_umx};
    /// @brief encoding for: guest_cs_limit
    constexpr auto VMCS_GUEST_CS_LIMIT{0x4802_umx};
    /// @brief encoding for: guest_ss_limit
    constexpr auto VMCS_GUEST_SS_LIMIT{0x4804_umx};
    /// @brief encoding for: guest_ds_limit
    constexpr auto VMCS_GUEST_DS_LIMIT{0x4806_umx};
    /// @brief encoding for: guest_fs_limit
    constexpr auto VMCS_GUEST_FS_LIMIT{0x4808_umx};
    /// @brief encoding for: guest_gs_limit
    constexpr auto VMCS_GUEST_GS_LIMIT{0x480A_umx};
    /// @brief encoding for: guest_ldtr_limit
    constexpr auto VMCS_GUEST_LDTR_LIMIT{0x480C_umx};
    /// @brief encoding for: guest_tr_limit
    constexpr auto VMCS_GUEST_TR_LIMIT{0x480E_umx};
    /// @brief encoding for: guest_gdtr_limit
    constexpr auto VMCS_GUEST_GDTR_LIMIT{0x4810_umx};
    /// @brief encoding for: guest_idtr_limit
    // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
    constexpr auto VMCS_GUEST_IDTR_LIMIT{0x4812_umx};
    /// @brief encoding for: guest_es_access_rights
    constexpr auto VMCS_GUEST_ES_ACCESS_RIGHTS{0x4814_umx};
    /// @brief encoding for: guest_cs_access_rights
    constexpr auto VMCS_GUEST_CS_ACCESS_RIGHTS{0x4816_umx};
    /// @brief encoding for: guest_ss_access_rights
    constexpr auto VMCS_GUEST_SS_ACCESS_RIGHTS{0x4818_umx};
    /// @brief encoding for: guest_ds_access_rights
    constexpr auto VMCS_GUEST_DS_ACCESS_RIGHTS{0x481A_umx};
    /// @brief encoding for: guest_fs_access_rights
    constexpr auto VMCS_GUEST_FS_ACCESS_RIGHTS{0x481C_umx};
    /// @brief encoding for: guest_gs_access_rights
    constexpr auto VMCS_GUEST_GS_ACCESS_RIGHTS{0x481E_umx};
    /// @brief encoding for: guest_ldtr_access_rights
    constexpr auto VMCS_GUEST_LDTR_ACCESS_RIGHTS{0x4820_umx};
    /// @brief encoding for: guest_tr_access_rights
    constexpr auto VMCS_GUEST_TR_ACCESS_RIGHTS{0x4822_umx};
    /// @brief encoding for: guest_interruptibility_state
    constexpr auto VMCS_GUEST_INTERRUPTIBILITY_STATE{0x4824_umx};
    /// @brief encoding for: guest_activity_state
    constexpr auto VMCS_GUEST_ACTIVITY_STATE{0x4826_umx};
    /// @brief encoding for: guest_smbase
    constexpr auto VMCS_GUEST_SMBASE{0x4828_umx};
    /// @brief encoding for: guest_sysenter_cs
    constexpr auto VMCS_GUEST_SYSENTER_CS{0x482A_umx};
    /// @brief encoding for: vmx_preemption_timer_value
    constexpr auto VMCS_VMX_PREEMPTION_TIMER_VALUE{0x482E_umx};

    /// @brief encoding for: host_sysenter_cs
    constexpr auto VMCS_HOST_SYSENTER_CS{0x4C00_umx};

    /// @brief encoding for: cr0_guest_host_mask
    constexpr auto VMCS_CR0_GUEST_HOST_MASK{0x6000_umx};
    /// @brief encoding for: cr4_guest_host_mask
    constexpr auto VMCS_CR4_GUEST_HOST_MASK{0x6002_umx};
    /// @brief encoding for: cr0_read_shadow
    constexpr auto VMCS_CR0_READ_SHADOW{0x6004_umx};
    /// @brief encoding for: cr4_read_shadow
    constexpr auto VMCS_CR4_READ_SHADOW{0x6006_umx};
    /// @brief encoding for: cr3_target_value0
    constexpr auto VMCS_CR3_TARGET_VALUE0{0x6008_umx};
    /// @brief encoding for: cr3_target_value1
    constexpr auto VMCS_CR3_TARGET_VALUE1{0x600A_umx};
    /// @brief encoding for: cr3_target_value2
    constexpr auto VMCS_CR3_TARGET_VALUE2{0x600C_umx};
    /// @brief encoding for: cr3_target_value3
    constexpr auto VMCS_CR3_TARGET_VALUE3{0x600E_umx};

    /// @brief encoding for: exit_qualification
    constexpr auto VMCS_EXIT_QUALIFICATION{0x6400_umx};
    /// @brief encoding for: io_rcx
    constexpr auto VMCS_IO_RCX{0x6402_umx};
    /// @brief encoding for: io_rsi
    constexpr auto VMCS_IO_RSI{0x6404_umx};
    /// @brief encoding for: io_rdi
    constexpr auto VMCS_IO_RDI{0x6406_umx};
    /// @brief encoding for: io_rip
    constexpr auto VMCS_IO_RIP{0x6408_umx};
    /// @brief encoding for: guest_linear_address
    constexpr auto VMCS_GUEST_LINEAR_ADDRESS{0x640A_umx};

    /// @brief encoding for: guest_cr0
    constexpr auto VMCS_GUEST_CR0{0x6800_umx};
    /// @brief encoding for: guest_cr3
    constexpr auto VMCS_GUEST_CR3{0x6802_umx};
    /// @brief encoding for: guest_cr4
    constexpr auto VMCS_GUEST_CR4{0x6804_umx};
    /// @brief encoding for: guest_es_base
    constexpr auto VMCS_GUEST_ES_BASE{0x6806_umx};
    /// @brief encoding for: guest_cs_base
    constexpr auto VMCS_GUEST_CS_BASE{0x6808_umx};
    /// @brief encoding for: guest_ss_base
    constexpr auto VMCS_GUEST_SS_BASE{0x680A_umx};
    /// @brief encoding for: guest_ds_base
    constexpr auto VMCS_GUEST_DS_BASE{0x680C_umx};
    /// @brief encoding for: guest_fs_base
    constexpr auto VMCS_GUEST_FS_BASE{0x680E_umx};
    /// @brief encoding for: guest_gs_base
    constexpr auto VMCS_GUEST_GS_BASE{0x6810_umx};
    /// @brief encoding for: guest_ldtr_base
    constexpr auto VMCS_GUEST_LDTR_BASE{0x6812_umx};
    /// @brief encoding for: guest_tr_base
    constexpr auto VMCS_GUEST_TR_BASE{0x6814_umx};
    /// @brief encoding for: guest_gdtr_base
    constexpr auto VMCS_GUEST_GDTR_BASE{0x6816_umx};
    /// @brief encoding for: guest_idtr_base
    // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
    constexpr auto VMCS_GUEST_IDTR_BASE{0x6818_umx};
    /// @brief encoding for: guest_dr7
    constexpr auto VMCS_GUEST_DR7{0x681A_umx};
    /// @brief encoding for: guest_rsp
    constexpr auto VMCS_GUEST_RSP{0x681C_umx};
    /// @brief encoding for: guest_rip
    constexpr auto VMCS_GUEST_RIP{0x681E_umx};
    /// @brief encoding for: guest_rflags
    constexpr auto VMCS_GUEST_RFLAGS{0x6820_umx};
    /// @brief encoding for: guest_pending_debug_exceptions
    constexpr auto VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS{0x6822_umx};
    /// @brief encoding for: guest_sysenter_esp
    constexpr auto VMCS_GUEST_SYSENTER_ESP{0x6824_umx};
    /// @brief encoding for: guest_sysenter_eip
    constexpr auto VMCS_GUEST_SYSENTER_EIP{0x6826_umx};

    /// @brief encoding for: host_cr0
    constexpr auto VMCS_HOST_CR0{0x6C00_umx};
    /// @brief encoding for: host_cr3
    constexpr auto VMCS_HOST_CR3{0x6C02_umx};
    /// @brief encoding for: host_cr4
    constexpr auto VMCS_HOST_CR4{0x6C04_umx};
    /// @brief encoding for: host_fs_base
    constexpr auto VMCS_HOST_FS_BASE{0x6C06_umx};
    /// @brief encoding for: host_gs_base
    constexpr auto VMCS_HOST_GS_BASE{0x6C08_umx};
    /// @brief encoding for: host_tr_base
    constexpr auto VMCS_HOST_TR_BASE{0x6C0A_umx};
    /// @brief encoding for: host_gdtr_base
    constexpr auto VMCS_HOST_GDTR_BASE{0x6C0C_umx};
    /// @brief encoding for: host_idtr_base
    constexpr auto VMCS_HOST_IDTR_BASE{0x6C0E_umx};
    /// @brief encoding for: host_sysenter_esp
    constexpr auto VMCS_HOST_SYSENTER_ESP{0x6C10_umx};
    /// @brief encoding for: host_sysenter_eip
    constexpr auto VMCS_HOST_SYSENTER_EIP{0x6C12_umx};
    /// @brief encoding for: host_rsp
    constexpr auto VMCS_HOST_RSP{0x6C14_umx};
    /// @brief encoding for: host_rip
    constexpr auto VMCS_HOST_RIP{0x6C16_umx};

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
        bsl::array<bsl::uint8, RESERVED_SIZE.get()> reserved;
    };
}

#pragma pack(pop)

#endif
