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

#ifndef BF_REG_T_HPP
#define BF_REG_T_HPP

#include <bsl/cstdint.hpp>

namespace syscall
{
    /// @brief stores the max value for a bf_reg_t
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    constexpr bsl::uint64 BF_MAX_REG_T{static_cast<bsl::uint64>(157)};

    /// <!-- description -->
    ///   @brief Defines which register is being requested by certain syscalls
    ///
    enum class bf_reg_t : bsl::uint64
    {
        /// @brief defines an unsupported register
        bf_reg_t_unsupported = static_cast<bsl::uint64>(0),
        /// @brief defines the rax register
        bf_reg_t_rax = static_cast<bsl::uint64>(1),
        /// @brief defines the rbx register
        bf_reg_t_rbx = static_cast<bsl::uint64>(2),
        /// @brief defines the rcx register
        bf_reg_t_rcx = static_cast<bsl::uint64>(3),
        /// @brief defines the rdx register
        bf_reg_t_rdx = static_cast<bsl::uint64>(4),
        /// @brief defines the rbp register
        bf_reg_t_rbp = static_cast<bsl::uint64>(5),
        /// @brief defines the rsi register
        bf_reg_t_rsi = static_cast<bsl::uint64>(6),
        /// @brief defines the rdi register
        bf_reg_t_rdi = static_cast<bsl::uint64>(7),
        /// @brief defines the r8 register
        bf_reg_t_r8 = static_cast<bsl::uint64>(8),
        /// @brief defines the r9 register
        bf_reg_t_r9 = static_cast<bsl::uint64>(9),
        /// @brief defines the r10 register
        bf_reg_t_r10 = static_cast<bsl::uint64>(10),
        /// @brief defines the r11 register
        bf_reg_t_r11 = static_cast<bsl::uint64>(11),
        /// @brief defines the r12 register
        bf_reg_t_r12 = static_cast<bsl::uint64>(12),
        /// @brief defines the r13 register
        bf_reg_t_r13 = static_cast<bsl::uint64>(13),
        /// @brief defines the r14 register
        bf_reg_t_r14 = static_cast<bsl::uint64>(14),
        /// @brief defines the r15 register
        bf_reg_t_r15 = static_cast<bsl::uint64>(15),
        /// @brief defines the bf_reg_t_cr2 register
        bf_reg_t_cr2 = static_cast<bsl::uint64>(16),
        /// @brief defines the bf_reg_t_dr6 register
        bf_reg_t_dr6 = static_cast<bsl::uint64>(17),
        /// @brief defines the bf_reg_t_ia32_star register
        bf_reg_t_ia32_star = static_cast<bsl::uint64>(18),
        /// @brief defines the bf_reg_t_ia32_lstar register
        bf_reg_t_ia32_lstar = static_cast<bsl::uint64>(19),
        /// @brief defines the bf_reg_t_ia32_cstar register
        bf_reg_t_ia32_cstar = static_cast<bsl::uint64>(20),
        /// @brief defines the bf_reg_t_ia32_fmask register
        bf_reg_t_ia32_fmask = static_cast<bsl::uint64>(21),
        /// @brief defines the bf_reg_t_ia32_kernel_gs_base register
        bf_reg_t_ia32_kernel_gs_base = static_cast<bsl::uint64>(22),
        /// @brief defines the virtual_processor_identifier register
        bf_reg_t_virtual_processor_identifier = static_cast<bsl::uint64>(23),
        /// @brief defines the posted_interrupt_notification_vector register
        bf_reg_t_posted_interrupt_notification_vector = static_cast<bsl::uint64>(24),
        /// @brief defines the eptp_index register
        bf_reg_t_eptp_index = static_cast<bsl::uint64>(25),
        /// @brief defines the guest_es_selector register
        bf_reg_t_es_selector = static_cast<bsl::uint64>(26),
        /// @brief defines the guest_cs_selector register
        bf_reg_t_cs_selector = static_cast<bsl::uint64>(27),
        /// @brief defines the guest_ss_selector register
        bf_reg_t_ss_selector = static_cast<bsl::uint64>(28),
        /// @brief defines the guest_ds_selector register
        bf_reg_t_ds_selector = static_cast<bsl::uint64>(29),
        /// @brief defines the guest_fs_selector register
        bf_reg_t_fs_selector = static_cast<bsl::uint64>(30),
        /// @brief defines the guest_gs_selector register
        bf_reg_t_gs_selector = static_cast<bsl::uint64>(31),
        /// @brief defines the guest_ldtr_selector register
        bf_reg_t_ldtr_selector = static_cast<bsl::uint64>(32),
        /// @brief defines the guest_tr_selector register
        bf_reg_t_tr_selector = static_cast<bsl::uint64>(33),
        /// @brief defines the guest_interrupt_status register
        bf_reg_t_interrupt_status = static_cast<bsl::uint64>(34),
        /// @brief defines the pml_index register
        bf_reg_t_pml_index = static_cast<bsl::uint64>(35),
        /// @brief defines the address_of_io_bitmap_a register
        bf_reg_t_address_of_io_bitmap_a = static_cast<bsl::uint64>(36),
        /// @brief defines the address_of_io_bitmap_b register
        bf_reg_t_address_of_io_bitmap_b = static_cast<bsl::uint64>(37),
        /// @brief defines the address_of_msr_bitmaps register
        bf_reg_t_address_of_msr_bitmaps = static_cast<bsl::uint64>(38),
        /// @brief defines the vmexit_msr_store_address register
        bf_reg_t_vmexit_msr_store_address = static_cast<bsl::uint64>(39),
        /// @brief defines the vmexit_msr_load_address register
        bf_reg_t_vmexit_msr_load_address = static_cast<bsl::uint64>(40),
        /// @brief defines the vmentry_msr_load_address register
        bf_reg_t_vmentry_msr_load_address = static_cast<bsl::uint64>(41),
        /// @brief defines the executive_vmcs_pointer register
        bf_reg_t_executive_vmcs_pointer = static_cast<bsl::uint64>(42),
        /// @brief defines the pml_address register
        bf_reg_t_pml_address = static_cast<bsl::uint64>(43),
        /// @brief defines the tsc_offset register
        bf_reg_t_tsc_offset = static_cast<bsl::uint64>(44),
        /// @brief defines the virtual_apic_address register
        bf_reg_t_virtual_apic_address = static_cast<bsl::uint64>(45),
        /// @brief defines the apic_access_address register
        bf_reg_t_apic_access_address = static_cast<bsl::uint64>(46),
        /// @brief defines the posted_interrupt_descriptor_address register
        bf_reg_t_posted_interrupt_descriptor_address = static_cast<bsl::uint64>(47),
        /// @brief defines the vm_function_controls register
        bf_reg_t_vm_function_controls = static_cast<bsl::uint64>(48),
        /// @brief defines the ept_pointer register
        bf_reg_t_ept_pointer = static_cast<bsl::uint64>(49),
        /// @brief defines the eoi_exit_bitmap0 register
        bf_reg_t_eoi_exit_bitmap0 = static_cast<bsl::uint64>(50),
        /// @brief defines the eoi_exit_bitmap1 register
        bf_reg_t_eoi_exit_bitmap1 = static_cast<bsl::uint64>(51),
        /// @brief defines the eoi_exit_bitmap2 register
        bf_reg_t_eoi_exit_bitmap2 = static_cast<bsl::uint64>(52),
        /// @brief defines the eoi_exit_bitmap3 register
        bf_reg_t_eoi_exit_bitmap3 = static_cast<bsl::uint64>(53),
        /// @brief defines the eptp_list_address register
        bf_reg_t_eptp_list_address = static_cast<bsl::uint64>(54),
        /// @brief defines the vmread_bitmap_address register
        bf_reg_t_vmread_bitmap_address = static_cast<bsl::uint64>(55),
        /// @brief defines the vmwrite_bitmap_address register
        bf_reg_t_vmwrite_bitmap_address = static_cast<bsl::uint64>(56),
        /// @brief defines the virt_exception_information_address register
        bf_reg_t_virt_exception_information_address = static_cast<bsl::uint64>(57),
        /// @brief defines the xss_exiting_bitmap register
        bf_reg_t_xss_exiting_bitmap = static_cast<bsl::uint64>(58),
        /// @brief defines the encls_exiting_bitmap register
        bf_reg_t_encls_exiting_bitmap = static_cast<bsl::uint64>(59),
        /// @brief defines the sub_page_permission_table_pointer register
        bf_reg_t_sub_page_permission_table_pointer = static_cast<bsl::uint64>(60),
        /// @brief defines the tls_multiplier register
        bf_reg_t_tls_multiplier = static_cast<bsl::uint64>(61),
        /// @brief defines the guest_physical_address register
        bf_reg_t_physical_address = static_cast<bsl::uint64>(62),
        /// @brief defines the vmcs_link_pointer register
        bf_reg_t_vmcs_link_pointer = static_cast<bsl::uint64>(63),
        /// @brief defines the guest_ia32_debugctl register
        bf_reg_t_ia32_debugctl = static_cast<bsl::uint64>(64),
        /// @brief defines the guest_ia32_pat register
        bf_reg_t_ia32_pat = static_cast<bsl::uint64>(65),
        /// @brief defines the guest_ia32_efer register
        bf_reg_t_ia32_efer = static_cast<bsl::uint64>(66),
        /// @brief defines the guest_ia32_perf_global_ctrl register
        bf_reg_t_ia32_perf_global_ctrl = static_cast<bsl::uint64>(67),
        /// @brief defines the guest_pdpte0 register
        bf_reg_t_pdpte0 = static_cast<bsl::uint64>(68),
        /// @brief defines the guest_pdpte1 register
        bf_reg_t_pdpte1 = static_cast<bsl::uint64>(69),
        /// @brief defines the guest_pdpte2 register
        bf_reg_t_pdpte2 = static_cast<bsl::uint64>(70),
        /// @brief defines the guest_pdpte3 register
        bf_reg_t_pdpte3 = static_cast<bsl::uint64>(71),
        /// @brief defines the guest_ia32_bndcfgs register
        bf_reg_t_ia32_bndcfgs = static_cast<bsl::uint64>(72),
        /// @brief defines the guest_rtit_ctl register
        bf_reg_t_rtit_ctl = static_cast<bsl::uint64>(73),
        /// @brief defines the pin_based_vm_execution_ctls register
        bf_reg_t_pin_based_vm_execution_ctls = static_cast<bsl::uint64>(74),
        /// @brief defines the primary_proc_based_vm_execution_ctls register
        bf_reg_t_primary_proc_based_vm_execution_ctls = static_cast<bsl::uint64>(75),
        /// @brief defines the exception_bitmap register
        bf_reg_t_exception_bitmap = static_cast<bsl::uint64>(76),
        /// @brief defines the page_fault_error_code_mask register
        bf_reg_t_page_fault_error_code_mask = static_cast<bsl::uint64>(77),
        /// @brief defines the page_fault_error_code_match register
        bf_reg_t_page_fault_error_code_match = static_cast<bsl::uint64>(78),
        /// @brief defines the cr3_target_count register
        bf_reg_t_cr3_target_count = static_cast<bsl::uint64>(79),
        /// @brief defines the vmexit_ctls register
        bf_reg_t_vmexit_ctls = static_cast<bsl::uint64>(80),
        /// @brief defines the vmexit_msr_store_count register
        bf_reg_t_vmexit_msr_store_count = static_cast<bsl::uint64>(81),
        /// @brief defines the vmexit_msr_load_count register
        bf_reg_t_vmexit_msr_load_count = static_cast<bsl::uint64>(82),
        /// @brief defines the vmentry_ctls register
        bf_reg_t_vmentry_ctls = static_cast<bsl::uint64>(83),
        /// @brief defines the vmentry_msr_load_count register
        bf_reg_t_vmentry_msr_load_count = static_cast<bsl::uint64>(84),
        /// @brief defines the vmentry_interrupt_information_field register
        bf_reg_t_vmentry_interrupt_information_field = static_cast<bsl::uint64>(85),
        /// @brief defines the vmentry_exception_error_code register
        bf_reg_t_vmentry_exception_error_code = static_cast<bsl::uint64>(86),
        /// @brief defines the vmentry_instruction_length register
        bf_reg_t_vmentry_instruction_length = static_cast<bsl::uint64>(87),
        /// @brief defines the tpr_threshold register
        bf_reg_t_tpr_threshold = static_cast<bsl::uint64>(88),
        /// @brief defines the secondary_proc_based_vm_execution_ctls register
        bf_reg_t_secondary_proc_based_vm_execution_ctls = static_cast<bsl::uint64>(89),
        /// @brief defines the ple_gap register
        bf_reg_t_ple_gap = static_cast<bsl::uint64>(90),
        /// @brief defines the ple_window register
        bf_reg_t_ple_window = static_cast<bsl::uint64>(91),
        /// @brief defines the vm_instruction_error register
        bf_reg_t_vm_instruction_error = static_cast<bsl::uint64>(92),
        /// @brief defines the exit_reason register
        bf_reg_t_exit_reason = static_cast<bsl::uint64>(93),
        /// @brief defines the vmexit_interruption_information register
        bf_reg_t_vmexit_interruption_information = static_cast<bsl::uint64>(94),
        /// @brief defines the vmexit_interruption_error_code register
        bf_reg_t_vmexit_interruption_error_code = static_cast<bsl::uint64>(95),
        /// @brief defines the idt_vectoring_information_field register
        bf_reg_t_idt_vectoring_information_field = static_cast<bsl::uint64>(96),
        /// @brief defines the idt_vectoring_error_code register
        bf_reg_t_idt_vectoring_error_code = static_cast<bsl::uint64>(97),
        /// @brief defines the vmexit_instruction_length register
        bf_reg_t_vmexit_instruction_length = static_cast<bsl::uint64>(98),
        /// @brief defines the vmexit_instruction_information register
        bf_reg_t_vmexit_instruction_information = static_cast<bsl::uint64>(99),
        /// @brief defines the guest_es_limit register
        bf_reg_t_es_limit = static_cast<bsl::uint64>(100),
        /// @brief defines the guest_cs_limit register
        bf_reg_t_cs_limit = static_cast<bsl::uint64>(101),
        /// @brief defines the guest_ss_limit register
        bf_reg_t_ss_limit = static_cast<bsl::uint64>(102),
        /// @brief defines the guest_ds_limit register
        bf_reg_t_ds_limit = static_cast<bsl::uint64>(103),
        /// @brief defines the guest_fs_limit register
        bf_reg_t_fs_limit = static_cast<bsl::uint64>(104),
        /// @brief defines the guest_gs_limit register
        bf_reg_t_gs_limit = static_cast<bsl::uint64>(105),
        /// @brief defines the guest_ldtr_limit register
        bf_reg_t_ldtr_limit = static_cast<bsl::uint64>(106),
        /// @brief defines the guest_tr_limit register
        bf_reg_t_tr_limit = static_cast<bsl::uint64>(107),
        /// @brief defines the guest_gdtr_limit register
        bf_reg_t_gdtr_limit = static_cast<bsl::uint64>(108),
        /// @brief defines the guest_idtr_limit register
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        bf_reg_t_idtr_limit = static_cast<bsl::uint64>(109),
        /// @brief defines the guest_es_attrib register
        bf_reg_t_es_attrib = static_cast<bsl::uint64>(110),
        /// @brief defines the guest_cs_attrib register
        bf_reg_t_cs_attrib = static_cast<bsl::uint64>(111),
        /// @brief defines the guest_ss_attrib register
        bf_reg_t_ss_attrib = static_cast<bsl::uint64>(112),
        /// @brief defines the guest_ds_attrib register
        bf_reg_t_ds_attrib = static_cast<bsl::uint64>(113),
        /// @brief defines the guest_fs_attrib register
        bf_reg_t_fs_attrib = static_cast<bsl::uint64>(114),
        /// @brief defines the guest_gs_attrib register
        bf_reg_t_gs_attrib = static_cast<bsl::uint64>(115),
        /// @brief defines the guest_ldtr_attrib register
        bf_reg_t_ldtr_attrib = static_cast<bsl::uint64>(116),
        /// @brief defines the guest_tr_attrib register
        bf_reg_t_tr_attrib = static_cast<bsl::uint64>(117),
        /// @brief defines the guest_interruptibility_state register
        bf_reg_t_interruptibility_state = static_cast<bsl::uint64>(118),
        /// @brief defines the guest_activity_state register
        bf_reg_t_activity_state = static_cast<bsl::uint64>(119),
        /// @brief defines the guest_smbase register
        bf_reg_t_smbase = static_cast<bsl::uint64>(120),
        /// @brief defines the guest_ia32_sysenter_cs register
        bf_reg_t_ia32_sysenter_cs = static_cast<bsl::uint64>(121),
        /// @brief defines the vmx_preemption_timer_value register
        bf_reg_t_vmx_preemption_timer_value = static_cast<bsl::uint64>(122),
        /// @brief defines the cr0_guest_host_mask register
        bf_reg_t_cr0_guest_host_mask = static_cast<bsl::uint64>(123),
        /// @brief defines the cr4_guest_host_mask register
        bf_reg_t_cr4_guest_host_mask = static_cast<bsl::uint64>(124),
        /// @brief defines the cr0_read_shadow register
        bf_reg_t_cr0_read_shadow = static_cast<bsl::uint64>(125),
        /// @brief defines the cr4_read_shadow register
        bf_reg_t_cr4_read_shadow = static_cast<bsl::uint64>(126),
        /// @brief defines the cr3_target_value0 register
        bf_reg_t_cr3_target_value0 = static_cast<bsl::uint64>(127),
        /// @brief defines the cr3_target_value1 register
        bf_reg_t_cr3_target_value1 = static_cast<bsl::uint64>(128),
        /// @brief defines the cr3_target_value2 register
        bf_reg_t_cr3_target_value2 = static_cast<bsl::uint64>(129),
        /// @brief defines the cr3_target_value3 register
        bf_reg_t_cr3_target_value3 = static_cast<bsl::uint64>(130),
        /// @brief defines the exit_qualification register
        bf_reg_t_exit_qualification = static_cast<bsl::uint64>(131),
        /// @brief defines the io_rcx register
        bf_reg_t_io_rcx = static_cast<bsl::uint64>(132),
        /// @brief defines the io_rsi register
        bf_reg_t_io_rsi = static_cast<bsl::uint64>(133),
        /// @brief defines the io_rdi register
        bf_reg_t_io_rdi = static_cast<bsl::uint64>(134),
        /// @brief defines the io_rip register
        bf_reg_t_io_rip = static_cast<bsl::uint64>(135),
        /// @brief defines the guest_linear_address register
        bf_reg_t_linear_address = static_cast<bsl::uint64>(136),
        /// @brief defines the guest_cr0 register
        bf_reg_t_cr0 = static_cast<bsl::uint64>(137),
        /// @brief defines the guest_cr3 register
        bf_reg_t_cr3 = static_cast<bsl::uint64>(138),
        /// @brief defines the guest_cr4 register
        bf_reg_t_cr4 = static_cast<bsl::uint64>(139),
        /// @brief defines the guest_es_base register
        bf_reg_t_es_base = static_cast<bsl::uint64>(140),
        /// @brief defines the guest_cs_base register
        bf_reg_t_cs_base = static_cast<bsl::uint64>(141),
        /// @brief defines the guest_ss_base register
        bf_reg_t_ss_base = static_cast<bsl::uint64>(142),
        /// @brief defines the guest_ds_base register
        bf_reg_t_ds_base = static_cast<bsl::uint64>(143),
        /// @brief defines the guest_fs_base register
        bf_reg_t_fs_base = static_cast<bsl::uint64>(144),
        /// @brief defines the guest_gs_base register
        bf_reg_t_gs_base = static_cast<bsl::uint64>(145),
        /// @brief defines the guest_ldtr_base register
        bf_reg_t_ldtr_base = static_cast<bsl::uint64>(146),
        /// @brief defines the guest_tr_base register
        bf_reg_t_tr_base = static_cast<bsl::uint64>(147),
        /// @brief defines the guest_gdtr_base register
        bf_reg_t_gdtr_base = static_cast<bsl::uint64>(148),
        /// @brief defines the guest_idtr_base register
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        bf_reg_t_idtr_base = static_cast<bsl::uint64>(149),
        /// @brief defines the guest_dr7 register
        bf_reg_t_dr7 = static_cast<bsl::uint64>(150),
        /// @brief defines the guest_rsp register
        bf_reg_t_rsp = static_cast<bsl::uint64>(151),
        /// @brief defines the guest_rip register
        bf_reg_t_rip = static_cast<bsl::uint64>(152),
        /// @brief defines the guest_rflags register
        bf_reg_t_rflags = static_cast<bsl::uint64>(153),
        /// @brief defines the guest_pending_debug_exceptions register
        bf_reg_t_pending_debug_exceptions = static_cast<bsl::uint64>(154),
        /// @brief defines the guest_ia32_sysenter_esp register
        bf_reg_t_ia32_sysenter_esp = static_cast<bsl::uint64>(155),
        /// @brief defines the guest_ia32_sysenter_eip register
        bf_reg_t_ia32_sysenter_eip = static_cast<bsl::uint64>(156),
        /// @brief defines an invalid bf_reg_t
        bf_reg_t_invalid = static_cast<bsl::uint64>(BF_MAX_REG_T)
    };
}

#endif
