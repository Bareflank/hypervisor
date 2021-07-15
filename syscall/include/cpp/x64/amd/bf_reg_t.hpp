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
    ///   @brief Defines which register to use for read/write
    ///
    enum class bf_reg_t : bsl::uint64
    {
        /// @brief defines the rbx register
        bf_reg_t_rbx = (1_u64).get(),
        /// @brief defines the rcx register
        bf_reg_t_rcx = (2_u64).get(),
        /// @brief defines the rdx register
        bf_reg_t_rdx = (3_u64).get(),
        /// @brief defines the rbp register
        bf_reg_t_rbp = (4_u64).get(),
        /// @brief defines the rsi register
        bf_reg_t_rsi = (5_u64).get(),
        /// @brief defines the rdi register
        bf_reg_t_rdi = (6_u64).get(),
        /// @brief defines the r8 register
        bf_reg_t_r8 = (7_u64).get(),
        /// @brief defines the r9 register
        bf_reg_t_r9 = (8_u64).get(),
        /// @brief defines the r10 register
        bf_reg_t_r10 = (9_u64).get(),
        /// @brief defines the r11 register
        bf_reg_t_r11 = (10_u64).get(),
        /// @brief defines the r12 register
        bf_reg_t_r12 = (11_u64).get(),
        /// @brief defines the r13 register
        bf_reg_t_r13 = (12_u64).get(),
        /// @brief defines the r14 register
        bf_reg_t_r14 = (13_u64).get(),
        /// @brief defines the r15 register
        bf_reg_t_r15 = (14_u64).get(),

        /// @brief defines the intercept_cr_read register in the VMCB
        bf_reg_t_intercept_cr_read = (15_u64).get(),
        /// @brief defines the intercept_cr_write register in the VMCB
        bf_reg_t_intercept_cr_write = (16_u64).get(),
        /// @brief defines the intercept_dr_read register in the VMCB
        bf_reg_t_intercept_dr_read = (17_u64).get(),
        /// @brief defines the intercept_dr_write register in the VMCB
        bf_reg_t_intercept_dr_write = (18_u64).get(),
        /// @brief defines the intercept_exception register in the VMCB
        bf_reg_t_intercept_exception = (19_u64).get(),
        /// @brief defines the intercept_instruction1 register in the VMCB
        bf_reg_t_intercept_instruction1 = (20_u64).get(),
        /// @brief defines the intercept_instruction2 register in the VMCB
        bf_reg_t_intercept_instruction2 = (21_u64).get(),
        /// @brief defines the intercept_instruction3 register in the VMCB
        bf_reg_t_intercept_instruction3 = (22_u64).get(),
        /// @brief defines the pause_filter_threshold register in the VMCB
        bf_reg_t_pause_filter_threshold = (23_u64).get(),
        /// @brief defines the pause_filter_count register in the VMCB
        bf_reg_t_pause_filter_count = (24_u64).get(),
        /// @brief defines the iopm_base_pa register in the VMCB
        bf_reg_t_iopm_base_pa = (25_u64).get(),
        /// @brief defines the msrpm_base_pa register in the VMCB
        bf_reg_t_msrpm_base_pa = (26_u64).get(),
        /// @brief defines the tsc_offset register in the VMCB
        bf_reg_t_tsc_offset = (27_u64).get(),
        /// @brief defines the guest_asid register in the VMCB
        bf_reg_t_guest_asid = (28_u64).get(),
        /// @brief defines the tlb_control register in the VMCB
        bf_reg_t_tlb_control = (29_u64).get(),
        /// @brief defines the virtual_interrupt_a register in the VMCB
        bf_reg_t_virtual_interrupt_a = (30_u64).get(),
        /// @brief defines the virtual_interrupt_b register in the VMCB
        bf_reg_t_virtual_interrupt_b = (31_u64).get(),
        /// @brief defines the exitcode register in the VMCB
        bf_reg_t_exitcode = (32_u64).get(),
        /// @brief defines the exitinfo1 register in the VMCB
        bf_reg_t_exitinfo1 = (33_u64).get(),
        /// @brief defines the exitinfo2 register in the VMCB
        bf_reg_t_exitinfo2 = (34_u64).get(),
        /// @brief defines the exitininfo register in the VMCB
        bf_reg_t_exitininfo = (35_u64).get(),
        /// @brief defines the ctls1 register in the VMCB
        bf_reg_t_ctls1 = (36_u64).get(),
        /// @brief defines the avic_apic_bar register in the VMCB
        bf_reg_t_avic_apic_bar = (37_u64).get(),
        /// @brief defines the guest_pa_of_ghcb register in the VMCB
        bf_reg_t_guest_pa_of_ghcb = (38_u64).get(),
        /// @brief defines the eventinj register in the VMCB
        bf_reg_t_eventinj = (39_u64).get(),
        /// @brief defines the n_cr3 register in the VMCB
        bf_reg_t_n_cr3 = (40_u64).get(),
        /// @brief defines the ctls2 register in the VMCB
        bf_reg_t_ctls2 = (41_u64).get(),
        /// @brief defines the vmcb_clean_bits register in the VMCB
        bf_reg_t_vmcb_clean_bits = (42_u64).get(),
        /// @brief defines the nrip register in the VMCB
        bf_reg_t_nrip = (43_u64).get(),
        /// @brief defines the number_of_bytes_fetched register in the VMCB
        bf_reg_t_number_of_bytes_fetched = (44_u64).get(),
        /// @brief defines the avic_apic_backing_page_ptr register in the VMCB
        bf_reg_t_avic_apic_backing_page_ptr = (45_u64).get(),
        /// @brief defines the avic_logical_table_ptr register in the VMCB
        bf_reg_t_avic_logical_table_ptr = (46_u64).get(),
        /// @brief defines the avic_physical_table_ptr register in the VMCB
        bf_reg_t_avic_physical_table_ptr = (47_u64).get(),
        /// @brief defines the vmsa_ptr register in the VMCB
        bf_reg_t_vmsa_ptr = (48_u64).get(),
        /// @brief defines the es_selector register in the VMCB
        bf_reg_t_es_selector = (49_u64).get(),
        /// @brief defines the es_attrib register in the VMCB
        bf_reg_t_es_attrib = (50_u64).get(),
        /// @brief defines the es_limit register in the VMCB
        bf_reg_t_es_limit = (51_u64).get(),
        /// @brief defines the es_base register in the VMCB
        bf_reg_t_es_base = (52_u64).get(),
        /// @brief defines the cs_selector register in the VMCB
        bf_reg_t_cs_selector = (53_u64).get(),
        /// @brief defines the cs_attrib register in the VMCB
        bf_reg_t_cs_attrib = (54_u64).get(),
        /// @brief defines the cs_limit register in the VMCB
        bf_reg_t_cs_limit = (55_u64).get(),
        /// @brief defines the cs_base register in the VMCB
        bf_reg_t_cs_base = (56_u64).get(),
        /// @brief defines the ss_selector register in the VMCB
        bf_reg_t_ss_selector = (57_u64).get(),
        /// @brief defines the ss_attrib register in the VMCB
        bf_reg_t_ss_attrib = (58_u64).get(),
        /// @brief defines the ss_limit register in the VMCB
        bf_reg_t_ss_limit = (59_u64).get(),
        /// @brief defines the ss_base register in the VMCB
        bf_reg_t_ss_base = (60_u64).get(),
        /// @brief defines the ds_selector register in the VMCB
        bf_reg_t_ds_selector = (61_u64).get(),
        /// @brief defines the ds_attrib register in the VMCB
        bf_reg_t_ds_attrib = (62_u64).get(),
        /// @brief defines the ds_limit register in the VMCB
        bf_reg_t_ds_limit = (63_u64).get(),
        /// @brief defines the ds_base register in the VMCB
        bf_reg_t_ds_base = (64_u64).get(),
        /// @brief defines the fs_selector register in the VMCB
        bf_reg_t_fs_selector = (65_u64).get(),
        /// @brief defines the fs_attrib register in the VMCB
        bf_reg_t_fs_attrib = (66_u64).get(),
        /// @brief defines the fs_limit register in the VMCB
        bf_reg_t_fs_limit = (67_u64).get(),
        /// @brief defines the fs_base register in the VMCB
        bf_reg_t_fs_base = (68_u64).get(),
        /// @brief defines the gs_selector register in the VMCB
        bf_reg_t_gs_selector = (69_u64).get(),
        /// @brief defines the gs_attrib register in the VMCB
        bf_reg_t_gs_attrib = (70_u64).get(),
        /// @brief defines the gs_limit register in the VMCB
        bf_reg_t_gs_limit = (71_u64).get(),
        /// @brief defines the gs_base register in the VMCB
        bf_reg_t_gs_base = (72_u64).get(),
        /// @brief defines the gdtr_selector register in the VMCB
        bf_reg_t_gdtr_selector = (73_u64).get(),
        /// @brief defines the gdtr_attrib register in the VMCB
        bf_reg_t_gdtr_attrib = (74_u64).get(),
        /// @brief defines the gdtr_limit register in the VMCB
        bf_reg_t_gdtr_limit = (75_u64).get(),
        /// @brief defines the gdtr_base register in the VMCB
        bf_reg_t_gdtr_base = (76_u64).get(),
        /// @brief defines the ldtr_selector register in the VMCB
        bf_reg_t_ldtr_selector = (77_u64).get(),
        /// @brief defines the ldtr_attrib register in the VMCB
        bf_reg_t_ldtr_attrib = (78_u64).get(),
        /// @brief defines the ldtr_limit register in the VMCB
        bf_reg_t_ldtr_limit = (79_u64).get(),
        /// @brief defines the ldtr_base register in the VMCB
        bf_reg_t_ldtr_base = (80_u64).get(),
        /// @brief defines the idtr_selector register in the VMCB
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        bf_reg_t_idtr_selector = (81_u64).get(),
        /// @brief defines the idtr_attrib register in the VMCB
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        bf_reg_t_idtr_attrib = (82_u64).get(),
        /// @brief defines the idtr_limit register in the VMCB
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        bf_reg_t_idtr_limit = (83_u64).get(),
        /// @brief defines the idtr_base register in the VMCB
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        bf_reg_t_idtr_base = (84_u64).get(),
        /// @brief defines the tr_selector register in the VMCB
        bf_reg_t_tr_selector = (85_u64).get(),
        /// @brief defines the tr_attrib register in the VMCB
        bf_reg_t_tr_attrib = (86_u64).get(),
        /// @brief defines the tr_limit register in the VMCB
        bf_reg_t_tr_limit = (87_u64).get(),
        /// @brief defines the tr_base register in the VMCB
        bf_reg_t_tr_base = (88_u64).get(),
        /// @brief defines the cpl register in the VMCB
        bf_reg_t_cpl = (89_u64).get(),
        /// @brief defines the efer register in the VMCB
        bf_reg_t_efer = (90_u64).get(),
        /// @brief defines the cr4 register in the VMCB
        bf_reg_t_cr4 = (91_u64).get(),
        /// @brief defines the cr3 register in the VMCB
        bf_reg_t_cr3 = (92_u64).get(),
        /// @brief defines the cr0 register in the VMCB
        bf_reg_t_cr0 = (93_u64).get(),
        /// @brief defines the dr7 register in the VMCB
        bf_reg_t_dr7 = (94_u64).get(),
        /// @brief defines the dr6 register in the VMCB
        bf_reg_t_dr6 = (95_u64).get(),
        /// @brief defines the rflags register in the VMCB
        bf_reg_t_rflags = (96_u64).get(),
        /// @brief defines the rip register in the VMCB
        bf_reg_t_rip = (97_u64).get(),
        /// @brief defines the rsp register in the VMCB
        bf_reg_t_rsp = (98_u64).get(),
        /// @brief defines the rax register in the VMCB
        bf_reg_t_rax = (99_u64).get(),
        /// @brief defines the star register in the VMCB
        bf_reg_t_star = (100_u64).get(),
        /// @brief defines the lstar register in the VMCB
        bf_reg_t_lstar = (101_u64).get(),
        /// @brief defines the cstar register in the VMCB
        bf_reg_t_cstar = (102_u64).get(),
        /// @brief defines the sfmask register in the VMCB
        bf_reg_t_sfmask = (103_u64).get(),
        /// @brief defines the kernel_gs_base register in the VMCB
        bf_reg_t_kernel_gs_base = (104_u64).get(),
        /// @brief defines the sysenter_cs register in the VMCB
        bf_reg_t_sysenter_cs = (105_u64).get(),
        /// @brief defines the sysenter_esp register in the VMCB
        bf_reg_t_sysenter_esp = (106_u64).get(),
        /// @brief defines the sysenter_eip register in the VMCB
        bf_reg_t_sysenter_eip = (107_u64).get(),
        /// @brief defines the cr2 register in the VMCB
        bf_reg_t_cr2 = (108_u64).get(),
        /// @brief defines the g_pat register in the VMCB
        bf_reg_t_g_pat = (109_u64).get(),
        /// @brief defines the dbgctl register in the VMCB
        bf_reg_t_dbgctl = (110_u64).get(),
        /// @brief defines the br_from register in the VMCB
        bf_reg_t_br_from = (112_u64).get(),
        /// @brief defines the br_to register in the VMCB
        bf_reg_t_br_to = (113_u64).get(),
        /// @brief defines the lastexcpfrom register in the VMCB
        bf_reg_t_lastexcpfrom = (114_u64).get(),
        /// @brief defines the lastexcpto register in the VMCB
        bf_reg_t_lastexcpto = (115_u64).get()
    };
}

#endif
