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

#include <bsl/convert.hpp>
#include <bsl/cstdint.hpp>

namespace syscall
{
    /// <!-- description -->
    ///   @brief Defines which register is being requested by certain syscalls
    ///
    enum class bf_reg_t : bsl::uint64
    {
        /// @brief defines the rax register
        bf_reg_t_rax = (1_u64).get(),
        /// @brief defines the rbx register
        bf_reg_t_rbx = (2_u64).get(),
        /// @brief defines the rcx register
        bf_reg_t_rcx = (3_u64).get(),
        /// @brief defines the rdx register
        bf_reg_t_rdx = (4_u64).get(),
        /// @brief defines the rbp register
        bf_reg_t_rbp = (5_u64).get(),
        /// @brief defines the rsi register
        bf_reg_t_rsi = (6_u64).get(),
        /// @brief defines the rdi register
        bf_reg_t_rdi = (7_u64).get(),
        /// @brief defines the r8 register
        bf_reg_t_r8 = (8_u64).get(),
        /// @brief defines the r9 register
        bf_reg_t_r9 = (9_u64).get(),
        /// @brief defines the r10 register
        bf_reg_t_r10 = (10_u64).get(),
        /// @brief defines the r11 register
        bf_reg_t_r11 = (11_u64).get(),
        /// @brief defines the r12 register
        bf_reg_t_r12 = (12_u64).get(),
        /// @brief defines the r13 register
        bf_reg_t_r13 = (13_u64).get(),
        /// @brief defines the r14 register
        bf_reg_t_r14 = (14_u64).get(),
        /// @brief defines the r15 register
        bf_reg_t_r15 = (15_u64).get(),
        /// @brief defines the bf_reg_t_guest_cr2 register
        bf_reg_t_guest_cr2 = (16_u64).get(),
        /// @brief defines the bf_reg_t_guest_dr6 register
        bf_reg_t_guest_dr6 = (17_u64).get(),
        /// @brief defines the bf_reg_t_guest_ia32_star register
        bf_reg_t_guest_ia32_star = (18_u64).get(),
        /// @brief defines the bf_reg_t_guest_ia32_lstar register
        bf_reg_t_guest_ia32_lstar = (19_u64).get(),
        /// @brief defines the bf_reg_t_guest_ia32_cstar register
        bf_reg_t_guest_ia32_cstar = (20_u64).get(),
        /// @brief defines the bf_reg_t_guest_ia32_fmask register
        bf_reg_t_guest_ia32_fmask = (21_u64).get(),
        /// @brief defines the bf_reg_t_guest_ia32_kernel_gs_base register
        bf_reg_t_guest_ia32_kernel_gs_base = (22_u64).get(),
        /// @brief defines the virtual_processor_identifier register
        bf_reg_t_virtual_processor_identifier = (23_u64).get(),
        /// @brief defines the posted_interrupt_notification_vector register
        bf_reg_t_posted_interrupt_notification_vector = (24_u64).get(),
        /// @brief defines the eptp_index register
        bf_reg_t_eptp_index = (25_u64).get(),
        /// @brief defines the guest_es_selector register
        bf_reg_t_guest_es_selector = (26_u64).get(),
        /// @brief defines the guest_cs_selector register
        bf_reg_t_guest_cs_selector = (27_u64).get(),
        /// @brief defines the guest_ss_selector register
        bf_reg_t_guest_ss_selector = (28_u64).get(),
        /// @brief defines the guest_ds_selector register
        bf_reg_t_guest_ds_selector = (29_u64).get(),
        /// @brief defines the guest_fs_selector register
        bf_reg_t_guest_fs_selector = (30_u64).get(),
        /// @brief defines the guest_gs_selector register
        bf_reg_t_guest_gs_selector = (31_u64).get(),
        /// @brief defines the guest_ldtr_selector register
        bf_reg_t_guest_ldtr_selector = (32_u64).get(),
        /// @brief defines the guest_tr_selector register
        bf_reg_t_guest_tr_selector = (33_u64).get(),
        /// @brief defines the guest_interrupt_status register
        bf_reg_t_guest_interrupt_status = (34_u64).get(),
        /// @brief defines the pml_index register
        bf_reg_t_pml_index = (35_u64).get(),
        /// @brief defines the address_of_io_bitmap_a register
        bf_reg_t_address_of_io_bitmap_a = (36_u64).get(),
        /// @brief defines the address_of_io_bitmap_b register
        bf_reg_t_address_of_io_bitmap_b = (37_u64).get(),
        /// @brief defines the address_of_msr_bitmaps register
        bf_reg_t_address_of_msr_bitmaps = (38_u64).get(),
        /// @brief defines the vmexit_msr_store_address register
        bf_reg_t_vmexit_msr_store_address = (39_u64).get(),
        /// @brief defines the vmexit_msr_load_address register
        bf_reg_t_vmexit_msr_load_address = (40_u64).get(),
        /// @brief defines the vmentry_msr_load_address register
        bf_reg_t_vmentry_msr_load_address = (41_u64).get(),
        /// @brief defines the executive_vmcs_pointer register
        bf_reg_t_executive_vmcs_pointer = (42_u64).get(),
        /// @brief defines the pml_address register
        bf_reg_t_pml_address = (43_u64).get(),
        /// @brief defines the tsc_offset register
        bf_reg_t_tsc_offset = (44_u64).get(),
        /// @brief defines the virtual_apic_address register
        bf_reg_t_virtual_apic_address = (45_u64).get(),
        /// @brief defines the apic_access_address register
        bf_reg_t_apic_access_address = (46_u64).get(),
        /// @brief defines the posted_interrupt_descriptor_address register
        bf_reg_t_posted_interrupt_descriptor_address = (47_u64).get(),
        /// @brief defines the vm_function_controls register
        bf_reg_t_vm_function_controls = (48_u64).get(),
        /// @brief defines the ept_pointer register
        bf_reg_t_ept_pointer = (49_u64).get(),
        /// @brief defines the eoi_exit_bitmap0 register
        bf_reg_t_eoi_exit_bitmap0 = (50_u64).get(),
        /// @brief defines the eoi_exit_bitmap1 register
        bf_reg_t_eoi_exit_bitmap1 = (51_u64).get(),
        /// @brief defines the eoi_exit_bitmap2 register
        bf_reg_t_eoi_exit_bitmap2 = (52_u64).get(),
        /// @brief defines the eoi_exit_bitmap3 register
        bf_reg_t_eoi_exit_bitmap3 = (53_u64).get(),
        /// @brief defines the eptp_list_address register
        bf_reg_t_eptp_list_address = (54_u64).get(),
        /// @brief defines the vmread_bitmap_address register
        bf_reg_t_vmread_bitmap_address = (55_u64).get(),
        /// @brief defines the vmwrite_bitmap_address register
        bf_reg_t_vmwrite_bitmap_address = (56_u64).get(),
        /// @brief defines the virt_exception_information_address register
        bf_reg_t_virt_exception_information_address = (57_u64).get(),
        /// @brief defines the xss_exiting_bitmap register
        bf_reg_t_xss_exiting_bitmap = (58_u64).get(),
        /// @brief defines the encls_exiting_bitmap register
        bf_reg_t_encls_exiting_bitmap = (59_u64).get(),
        /// @brief defines the sub_page_permission_table_pointer register
        bf_reg_t_sub_page_permission_table_pointer = (60_u64).get(),
        /// @brief defines the tls_multiplier register
        bf_reg_t_tls_multiplier = (61_u64).get(),
        /// @brief defines the guest_physical_address register
        bf_reg_t_guest_physical_address = (62_u64).get(),
        /// @brief defines the vmcs_link_pointer register
        bf_reg_t_vmcs_link_pointer = (63_u64).get(),
        /// @brief defines the guest_ia32_debugctl register
        bf_reg_t_guest_ia32_debugctl = (64_u64).get(),
        /// @brief defines the guest_ia32_pat register
        bf_reg_t_guest_ia32_pat = (65_u64).get(),
        /// @brief defines the guest_ia32_efer register
        bf_reg_t_guest_ia32_efer = (66_u64).get(),
        /// @brief defines the guest_ia32_perf_global_ctrl register
        bf_reg_t_guest_ia32_perf_global_ctrl = (67_u64).get(),
        /// @brief defines the guest_pdpte0 register
        bf_reg_t_guest_pdpte0 = (68_u64).get(),
        /// @brief defines the guest_pdpte1 register
        bf_reg_t_guest_pdpte1 = (69_u64).get(),
        /// @brief defines the guest_pdpte2 register
        bf_reg_t_guest_pdpte2 = (70_u64).get(),
        /// @brief defines the guest_pdpte3 register
        bf_reg_t_guest_pdpte3 = (71_u64).get(),
        /// @brief defines the guest_ia32_bndcfgs register
        bf_reg_t_guest_ia32_bndcfgs = (72_u64).get(),
        /// @brief defines the guest_rtit_ctl register
        bf_reg_t_guest_rtit_ctl = (73_u64).get(),
        /// @brief defines the pin_based_vm_execution_ctls register
        bf_reg_t_pin_based_vm_execution_ctls = (74_u64).get(),
        /// @brief defines the primary_proc_based_vm_execution_ctls register
        bf_reg_t_primary_proc_based_vm_execution_ctls = (75_u64).get(),
        /// @brief defines the exception_bitmap register
        bf_reg_t_exception_bitmap = (76_u64).get(),
        /// @brief defines the page_fault_error_code_mask register
        bf_reg_t_page_fault_error_code_mask = (77_u64).get(),
        /// @brief defines the page_fault_error_code_match register
        bf_reg_t_page_fault_error_code_match = (78_u64).get(),
        /// @brief defines the cr3_target_count register
        bf_reg_t_cr3_target_count = (79_u64).get(),
        /// @brief defines the vmexit_ctls register
        bf_reg_t_vmexit_ctls = (80_u64).get(),
        /// @brief defines the vmexit_msr_store_count register
        bf_reg_t_vmexit_msr_store_count = (81_u64).get(),
        /// @brief defines the vmexit_msr_load_count register
        bf_reg_t_vmexit_msr_load_count = (82_u64).get(),
        /// @brief defines the vmentry_ctls register
        bf_reg_t_vmentry_ctls = (83_u64).get(),
        /// @brief defines the vmentry_msr_load_count register
        bf_reg_t_vmentry_msr_load_count = (84_u64).get(),
        /// @brief defines the vmentry_interrupt_information_field register
        bf_reg_t_vmentry_interrupt_information_field = (85_u64).get(),
        /// @brief defines the vmentry_exception_error_code register
        bf_reg_t_vmentry_exception_error_code = (86_u64).get(),
        /// @brief defines the vmentry_instruction_length register
        bf_reg_t_vmentry_instruction_length = (87_u64).get(),
        /// @brief defines the tpr_threshold register
        bf_reg_t_tpr_threshold = (88_u64).get(),
        /// @brief defines the secondary_proc_based_vm_execution_ctls register
        bf_reg_t_secondary_proc_based_vm_execution_ctls = (89_u64).get(),
        /// @brief defines the ple_gap register
        bf_reg_t_ple_gap = (90_u64).get(),
        /// @brief defines the ple_window register
        bf_reg_t_ple_window = (91_u64).get(),
        /// @brief defines the vm_instruction_error register
        bf_reg_t_vm_instruction_error = (92_u64).get(),
        /// @brief defines the exit_reason register
        bf_reg_t_exit_reason = (93_u64).get(),
        /// @brief defines the vmexit_interruption_information register
        bf_reg_t_vmexit_interruption_information = (94_u64).get(),
        /// @brief defines the vmexit_interruption_error_code register
        bf_reg_t_vmexit_interruption_error_code = (95_u64).get(),
        /// @brief defines the idt_vectoring_information_field register
        bf_reg_t_idt_vectoring_information_field = (96_u64).get(),
        /// @brief defines the idt_vectoring_error_code register
        bf_reg_t_idt_vectoring_error_code = (97_u64).get(),
        /// @brief defines the vmexit_instruction_length register
        bf_reg_t_vmexit_instruction_length = (98_u64).get(),
        /// @brief defines the vmexit_instruction_information register
        bf_reg_t_vmexit_instruction_information = (99_u64).get(),
        /// @brief defines the guest_es_limit register
        bf_reg_t_guest_es_limit = (100_u64).get(),
        /// @brief defines the guest_cs_limit register
        bf_reg_t_guest_cs_limit = (101_u64).get(),
        /// @brief defines the guest_ss_limit register
        bf_reg_t_guest_ss_limit = (102_u64).get(),
        /// @brief defines the guest_ds_limit register
        bf_reg_t_guest_ds_limit = (103_u64).get(),
        /// @brief defines the guest_fs_limit register
        bf_reg_t_guest_fs_limit = (104_u64).get(),
        /// @brief defines the guest_gs_limit register
        bf_reg_t_guest_gs_limit = (105_u64).get(),
        /// @brief defines the guest_ldtr_limit register
        bf_reg_t_guest_ldtr_limit = (106_u64).get(),
        /// @brief defines the guest_tr_limit register
        bf_reg_t_guest_tr_limit = (107_u64).get(),
        /// @brief defines the guest_gdtr_limit register
        bf_reg_t_guest_gdtr_limit = (108_u64).get(),
        /// @brief defines the guest_idtr_limit register
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        bf_reg_t_guest_idtr_limit = (109_u64).get(),
        /// @brief defines the guest_es_access_rights register
        bf_reg_t_guest_es_access_rights = (110_u64).get(),
        /// @brief defines the guest_cs_access_rights register
        bf_reg_t_guest_cs_access_rights = (111_u64).get(),
        /// @brief defines the guest_ss_access_rights register
        bf_reg_t_guest_ss_access_rights = (112_u64).get(),
        /// @brief defines the guest_ds_access_rights register
        bf_reg_t_guest_ds_access_rights = (113_u64).get(),
        /// @brief defines the guest_fs_access_rights register
        bf_reg_t_guest_fs_access_rights = (114_u64).get(),
        /// @brief defines the guest_gs_access_rights register
        bf_reg_t_guest_gs_access_rights = (115_u64).get(),
        /// @brief defines the guest_ldtr_access_rights register
        bf_reg_t_guest_ldtr_access_rights = (116_u64).get(),
        /// @brief defines the guest_tr_access_rights register
        bf_reg_t_guest_tr_access_rights = (117_u64).get(),
        /// @brief defines the guest_interruptibility_state register
        bf_reg_t_guest_interruptibility_state = (118_u64).get(),
        /// @brief defines the guest_activity_state register
        bf_reg_t_guest_activity_state = (119_u64).get(),
        /// @brief defines the guest_smbase register
        bf_reg_t_guest_smbase = (120_u64).get(),
        /// @brief defines the guest_ia32_sysenter_cs register
        bf_reg_t_guest_ia32_sysenter_cs = (121_u64).get(),
        /// @brief defines the vmx_preemption_timer_value register
        bf_reg_t_vmx_preemption_timer_value = (122_u64).get(),
        /// @brief defines the cr0_guest_host_mask register
        bf_reg_t_cr0_guest_host_mask = (123_u64).get(),
        /// @brief defines the cr4_guest_host_mask register
        bf_reg_t_cr4_guest_host_mask = (124_u64).get(),
        /// @brief defines the cr0_read_shadow register
        bf_reg_t_cr0_read_shadow = (125_u64).get(),
        /// @brief defines the cr4_read_shadow register
        bf_reg_t_cr4_read_shadow = (126_u64).get(),
        /// @brief defines the cr3_target_value0 register
        bf_reg_t_cr3_target_value0 = (127_u64).get(),
        /// @brief defines the cr3_target_value1 register
        bf_reg_t_cr3_target_value1 = (128_u64).get(),
        /// @brief defines the cr3_target_value2 register
        bf_reg_t_cr3_target_value2 = (129_u64).get(),
        /// @brief defines the cr3_target_value3 register
        bf_reg_t_cr3_target_value3 = (130_u64).get(),
        /// @brief defines the exit_qualification register
        bf_reg_t_exit_qualification = (131_u64).get(),
        /// @brief defines the io_rcx register
        bf_reg_t_io_rcx = (132_u64).get(),
        /// @brief defines the io_rsi register
        bf_reg_t_io_rsi = (133_u64).get(),
        /// @brief defines the io_rdi register
        bf_reg_t_io_rdi = (134_u64).get(),
        /// @brief defines the io_rip register
        bf_reg_t_io_rip = (135_u64).get(),
        /// @brief defines the guest_linear_address register
        bf_reg_t_guest_linear_address = (136_u64).get(),
        /// @brief defines the guest_cr0 register
        bf_reg_t_guest_cr0 = (137_u64).get(),
        /// @brief defines the guest_cr3 register
        bf_reg_t_guest_cr3 = (138_u64).get(),
        /// @brief defines the guest_cr4 register
        bf_reg_t_guest_cr4 = (139_u64).get(),
        /// @brief defines the guest_es_base register
        bf_reg_t_guest_es_base = (140_u64).get(),
        /// @brief defines the guest_cs_base register
        bf_reg_t_guest_cs_base = (141_u64).get(),
        /// @brief defines the guest_ss_base register
        bf_reg_t_guest_ss_base = (142_u64).get(),
        /// @brief defines the guest_ds_base register
        bf_reg_t_guest_ds_base = (143_u64).get(),
        /// @brief defines the guest_fs_base register
        bf_reg_t_guest_fs_base = (144_u64).get(),
        /// @brief defines the guest_gs_base register
        bf_reg_t_guest_gs_base = (145_u64).get(),
        /// @brief defines the guest_ldtr_base register
        bf_reg_t_guest_ldtr_base = (146_u64).get(),
        /// @brief defines the guest_tr_base register
        bf_reg_t_guest_tr_base = (147_u64).get(),
        /// @brief defines the guest_gdtr_base register
        bf_reg_t_guest_gdtr_base = (148_u64).get(),
        /// @brief defines the guest_idtr_base register
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        bf_reg_t_guest_idtr_base = (149_u64).get(),
        /// @brief defines the guest_dr7 register
        bf_reg_t_guest_dr7 = (150_u64).get(),
        /// @brief defines the guest_rsp register
        bf_reg_t_guest_rsp = (151_u64).get(),
        /// @brief defines the guest_rip register
        bf_reg_t_guest_rip = (152_u64).get(),
        /// @brief defines the guest_rflags register
        bf_reg_t_guest_rflags = (153_u64).get(),
        /// @brief defines the guest_pending_debug_exceptions register
        bf_reg_t_guest_pending_debug_exceptions = (154_u64).get(),
        /// @brief defines the guest_ia32_sysenter_esp register
        bf_reg_t_guest_ia32_sysenter_esp = (155_u64).get(),
        /// @brief defines the guest_ia32_sysenter_eip register
        bf_reg_t_guest_ia32_sysenter_eip = (156_u64).get()
    };
}

#endif
