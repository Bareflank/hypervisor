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
    constexpr bsl::uint64 BF_MAX_REG_T{static_cast<bsl::uint64>(116)};

    /// <!-- description -->
    ///   @brief Defines which register to use for read/write
    ///
    enum class bf_reg_t : bsl::uint64
    {
        /// @brief defines an unsupported register
        bf_reg_t_unsupported = static_cast<bsl::uint64>(0),
        /// @brief defines the rbx register
        bf_reg_t_rbx = static_cast<bsl::uint64>(1),
        /// @brief defines the rcx register
        bf_reg_t_rcx = static_cast<bsl::uint64>(2),
        /// @brief defines the rdx register
        bf_reg_t_rdx = static_cast<bsl::uint64>(3),
        /// @brief defines the rbp register
        bf_reg_t_rbp = static_cast<bsl::uint64>(4),
        /// @brief defines the rsi register
        bf_reg_t_rsi = static_cast<bsl::uint64>(5),
        /// @brief defines the rdi register
        bf_reg_t_rdi = static_cast<bsl::uint64>(6),
        /// @brief defines the r8 register
        bf_reg_t_r8 = static_cast<bsl::uint64>(7),
        /// @brief defines the r9 register
        bf_reg_t_r9 = static_cast<bsl::uint64>(8),
        /// @brief defines the r10 register
        bf_reg_t_r10 = static_cast<bsl::uint64>(9),
        /// @brief defines the r11 register
        bf_reg_t_r11 = static_cast<bsl::uint64>(10),
        /// @brief defines the r12 register
        bf_reg_t_r12 = static_cast<bsl::uint64>(11),
        /// @brief defines the r13 register
        bf_reg_t_r13 = static_cast<bsl::uint64>(12),
        /// @brief defines the r14 register
        bf_reg_t_r14 = static_cast<bsl::uint64>(13),
        /// @brief defines the r15 register
        bf_reg_t_r15 = static_cast<bsl::uint64>(14),
        /// @brief defines the intercept_cr_read register in the VMCB
        bf_reg_t_intercept_cr_read = static_cast<bsl::uint64>(15),
        /// @brief defines the intercept_cr_write register in the VMCB
        bf_reg_t_intercept_cr_write = static_cast<bsl::uint64>(16),
        /// @brief defines the intercept_dr_read register in the VMCB
        bf_reg_t_intercept_dr_read = static_cast<bsl::uint64>(17),
        /// @brief defines the intercept_dr_write register in the VMCB
        bf_reg_t_intercept_dr_write = static_cast<bsl::uint64>(18),
        /// @brief defines the intercept_exception register in the VMCB
        bf_reg_t_intercept_exception = static_cast<bsl::uint64>(19),
        /// @brief defines the intercept_instruction1 register in the VMCB
        bf_reg_t_intercept_instruction1 = static_cast<bsl::uint64>(20),
        /// @brief defines the intercept_instruction2 register in the VMCB
        bf_reg_t_intercept_instruction2 = static_cast<bsl::uint64>(21),
        /// @brief defines the intercept_instruction3 register in the VMCB
        bf_reg_t_intercept_instruction3 = static_cast<bsl::uint64>(22),
        /// @brief defines the pause_filter_threshold register in the VMCB
        bf_reg_t_pause_filter_threshold = static_cast<bsl::uint64>(23),
        /// @brief defines the pause_filter_count register in the VMCB
        bf_reg_t_pause_filter_count = static_cast<bsl::uint64>(24),
        /// @brief defines the iopm_base_pa register in the VMCB
        bf_reg_t_iopm_base_pa = static_cast<bsl::uint64>(25),
        /// @brief defines the msrpm_base_pa register in the VMCB
        bf_reg_t_msrpm_base_pa = static_cast<bsl::uint64>(26),
        /// @brief defines the tsc_offset register in the VMCB
        bf_reg_t_tsc_offset = static_cast<bsl::uint64>(27),
        /// @brief defines the guest_asid register in the VMCB
        bf_reg_t_guest_asid = static_cast<bsl::uint64>(28),
        /// @brief defines the tlb_control register in the VMCB
        bf_reg_t_tlb_control = static_cast<bsl::uint64>(29),
        /// @brief defines the virtual_interrupt_a register in the VMCB
        bf_reg_t_virtual_interrupt_a = static_cast<bsl::uint64>(30),
        /// @brief defines the virtual_interrupt_b register in the VMCB
        bf_reg_t_virtual_interrupt_b = static_cast<bsl::uint64>(31),
        /// @brief defines the exitcode register in the VMCB
        bf_reg_t_exitcode = static_cast<bsl::uint64>(32),
        /// @brief defines the exitinfo1 register in the VMCB
        bf_reg_t_exitinfo1 = static_cast<bsl::uint64>(33),
        /// @brief defines the exitinfo2 register in the VMCB
        bf_reg_t_exitinfo2 = static_cast<bsl::uint64>(34),
        /// @brief defines the exitininfo register in the VMCB
        bf_reg_t_exitininfo = static_cast<bsl::uint64>(35),
        /// @brief defines the ctls1 register in the VMCB
        bf_reg_t_ctls1 = static_cast<bsl::uint64>(36),
        /// @brief defines the avic_apic_bar register in the VMCB
        bf_reg_t_avic_apic_bar = static_cast<bsl::uint64>(37),
        /// @brief defines the guest_pa_of_ghcb register in the VMCB
        bf_reg_t_guest_pa_of_ghcb = static_cast<bsl::uint64>(38),
        /// @brief defines the eventinj register in the VMCB
        bf_reg_t_eventinj = static_cast<bsl::uint64>(39),
        /// @brief defines the n_cr3 register in the VMCB
        bf_reg_t_n_cr3 = static_cast<bsl::uint64>(40),
        /// @brief defines the ctls2 register in the VMCB
        bf_reg_t_ctls2 = static_cast<bsl::uint64>(41),
        /// @brief defines the vmcb_clean_bits register in the VMCB
        bf_reg_t_vmcb_clean_bits = static_cast<bsl::uint64>(42),
        /// @brief defines the nrip register in the VMCB
        bf_reg_t_nrip = static_cast<bsl::uint64>(43),
        /// @brief defines the number_of_bytes_fetched register in the VMCB
        bf_reg_t_number_of_bytes_fetched = static_cast<bsl::uint64>(44),
        /// @brief defines the avic_apic_backing_page_ptr register in the VMCB
        bf_reg_t_avic_apic_backing_page_ptr = static_cast<bsl::uint64>(45),
        /// @brief defines the avic_logical_table_ptr register in the VMCB
        bf_reg_t_avic_logical_table_ptr = static_cast<bsl::uint64>(46),
        /// @brief defines the avic_physical_table_ptr register in the VMCB
        bf_reg_t_avic_physical_table_ptr = static_cast<bsl::uint64>(47),
        /// @brief defines the vmsa_ptr register in the VMCB
        bf_reg_t_vmsa_ptr = static_cast<bsl::uint64>(48),
        /// @brief defines the es_selector register in the VMCB
        bf_reg_t_es_selector = static_cast<bsl::uint64>(49),
        /// @brief defines the es_attrib register in the VMCB
        bf_reg_t_es_attrib = static_cast<bsl::uint64>(50),
        /// @brief defines the es_limit register in the VMCB
        bf_reg_t_es_limit = static_cast<bsl::uint64>(51),
        /// @brief defines the es_base register in the VMCB
        bf_reg_t_es_base = static_cast<bsl::uint64>(52),
        /// @brief defines the cs_selector register in the VMCB
        bf_reg_t_cs_selector = static_cast<bsl::uint64>(53),
        /// @brief defines the cs_attrib register in the VMCB
        bf_reg_t_cs_attrib = static_cast<bsl::uint64>(54),
        /// @brief defines the cs_limit register in the VMCB
        bf_reg_t_cs_limit = static_cast<bsl::uint64>(55),
        /// @brief defines the cs_base register in the VMCB
        bf_reg_t_cs_base = static_cast<bsl::uint64>(56),
        /// @brief defines the ss_selector register in the VMCB
        bf_reg_t_ss_selector = static_cast<bsl::uint64>(57),
        /// @brief defines the ss_attrib register in the VMCB
        bf_reg_t_ss_attrib = static_cast<bsl::uint64>(58),
        /// @brief defines the ss_limit register in the VMCB
        bf_reg_t_ss_limit = static_cast<bsl::uint64>(59),
        /// @brief defines the ss_base register in the VMCB
        bf_reg_t_ss_base = static_cast<bsl::uint64>(60),
        /// @brief defines the ds_selector register in the VMCB
        bf_reg_t_ds_selector = static_cast<bsl::uint64>(61),
        /// @brief defines the ds_attrib register in the VMCB
        bf_reg_t_ds_attrib = static_cast<bsl::uint64>(62),
        /// @brief defines the ds_limit register in the VMCB
        bf_reg_t_ds_limit = static_cast<bsl::uint64>(63),
        /// @brief defines the ds_base register in the VMCB
        bf_reg_t_ds_base = static_cast<bsl::uint64>(64),
        /// @brief defines the fs_selector register in the VMCB
        bf_reg_t_fs_selector = static_cast<bsl::uint64>(65),
        /// @brief defines the fs_attrib register in the VMCB
        bf_reg_t_fs_attrib = static_cast<bsl::uint64>(66),
        /// @brief defines the fs_limit register in the VMCB
        bf_reg_t_fs_limit = static_cast<bsl::uint64>(67),
        /// @brief defines the fs_base register in the VMCB
        bf_reg_t_fs_base = static_cast<bsl::uint64>(68),
        /// @brief defines the gs_selector register in the VMCB
        bf_reg_t_gs_selector = static_cast<bsl::uint64>(69),
        /// @brief defines the gs_attrib register in the VMCB
        bf_reg_t_gs_attrib = static_cast<bsl::uint64>(70),
        /// @brief defines the gs_limit register in the VMCB
        bf_reg_t_gs_limit = static_cast<bsl::uint64>(71),
        /// @brief defines the gs_base register in the VMCB
        bf_reg_t_gs_base = static_cast<bsl::uint64>(72),
        /// @brief defines the gdtr_selector register in the VMCB
        bf_reg_t_gdtr_selector = static_cast<bsl::uint64>(73),
        /// @brief defines the gdtr_attrib register in the VMCB
        bf_reg_t_gdtr_attrib = static_cast<bsl::uint64>(74),
        /// @brief defines the gdtr_limit register in the VMCB
        bf_reg_t_gdtr_limit = static_cast<bsl::uint64>(75),
        /// @brief defines the gdtr_base register in the VMCB
        bf_reg_t_gdtr_base = static_cast<bsl::uint64>(76),
        /// @brief defines the ldtr_selector register in the VMCB
        bf_reg_t_ldtr_selector = static_cast<bsl::uint64>(77),
        /// @brief defines the ldtr_attrib register in the VMCB
        bf_reg_t_ldtr_attrib = static_cast<bsl::uint64>(78),
        /// @brief defines the ldtr_limit register in the VMCB
        bf_reg_t_ldtr_limit = static_cast<bsl::uint64>(79),
        /// @brief defines the ldtr_base register in the VMCB
        bf_reg_t_ldtr_base = static_cast<bsl::uint64>(80),
        /// @brief defines the idtr_selector register in the VMCB
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        bf_reg_t_idtr_selector = static_cast<bsl::uint64>(81),
        /// @brief defines the idtr_attrib register in the VMCB
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        bf_reg_t_idtr_attrib = static_cast<bsl::uint64>(82),
        /// @brief defines the idtr_limit register in the VMCB
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        bf_reg_t_idtr_limit = static_cast<bsl::uint64>(83),
        /// @brief defines the idtr_base register in the VMCB
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        bf_reg_t_idtr_base = static_cast<bsl::uint64>(84),
        /// @brief defines the tr_selector register in the VMCB
        bf_reg_t_tr_selector = static_cast<bsl::uint64>(85),
        /// @brief defines the tr_attrib register in the VMCB
        bf_reg_t_tr_attrib = static_cast<bsl::uint64>(86),
        /// @brief defines the tr_limit register in the VMCB
        bf_reg_t_tr_limit = static_cast<bsl::uint64>(87),
        /// @brief defines the tr_base register in the VMCB
        bf_reg_t_tr_base = static_cast<bsl::uint64>(88),
        /// @brief defines the cpl register in the VMCB
        bf_reg_t_cpl = static_cast<bsl::uint64>(89),
        /// @brief defines the efer register in the VMCB
        bf_reg_t_efer = static_cast<bsl::uint64>(90),
        /// @brief defines the cr4 register in the VMCB
        bf_reg_t_cr4 = static_cast<bsl::uint64>(91),
        /// @brief defines the cr3 register in the VMCB
        bf_reg_t_cr3 = static_cast<bsl::uint64>(92),
        /// @brief defines the cr0 register in the VMCB
        bf_reg_t_cr0 = static_cast<bsl::uint64>(93),
        /// @brief defines the dr7 register in the VMCB
        bf_reg_t_dr7 = static_cast<bsl::uint64>(94),
        /// @brief defines the dr6 register in the VMCB
        bf_reg_t_dr6 = static_cast<bsl::uint64>(95),
        /// @brief defines the rflags register in the VMCB
        bf_reg_t_rflags = static_cast<bsl::uint64>(96),
        /// @brief defines the rip register in the VMCB
        bf_reg_t_rip = static_cast<bsl::uint64>(97),
        /// @brief defines the rsp register in the VMCB
        bf_reg_t_rsp = static_cast<bsl::uint64>(98),
        /// @brief defines the rax register in the VMCB
        bf_reg_t_rax = static_cast<bsl::uint64>(99),
        /// @brief defines the star register in the VMCB
        bf_reg_t_star = static_cast<bsl::uint64>(100),
        /// @brief defines the lstar register in the VMCB
        bf_reg_t_lstar = static_cast<bsl::uint64>(101),
        /// @brief defines the cstar register in the VMCB
        bf_reg_t_cstar = static_cast<bsl::uint64>(102),
        /// @brief defines the fmask register in the VMCB
        bf_reg_t_fmask = static_cast<bsl::uint64>(103),
        /// @brief defines the kernel_gs_base register in the VMCB
        bf_reg_t_kernel_gs_base = static_cast<bsl::uint64>(104),
        /// @brief defines the sysenter_cs register in the VMCB
        bf_reg_t_sysenter_cs = static_cast<bsl::uint64>(105),
        /// @brief defines the sysenter_esp register in the VMCB
        bf_reg_t_sysenter_esp = static_cast<bsl::uint64>(106),
        /// @brief defines the sysenter_eip register in the VMCB
        bf_reg_t_sysenter_eip = static_cast<bsl::uint64>(107),
        /// @brief defines the cr2 register in the VMCB
        bf_reg_t_cr2 = static_cast<bsl::uint64>(108),
        /// @brief defines the pat register in the VMCB
        bf_reg_t_pat = static_cast<bsl::uint64>(109),
        /// @brief defines the dbgctl register in the VMCB
        bf_reg_t_dbgctl = static_cast<bsl::uint64>(110),
        /// @brief defines the br_from register in the VMCB
        bf_reg_t_br_from = static_cast<bsl::uint64>(112),
        /// @brief defines the br_to register in the VMCB
        bf_reg_t_br_to = static_cast<bsl::uint64>(113),
        /// @brief defines the lastexcpfrom register in the VMCB
        bf_reg_t_lastexcpfrom = static_cast<bsl::uint64>(114),
        /// @brief defines the lastexcpto register in the VMCB
        bf_reg_t_lastexcpto = static_cast<bsl::uint64>(115),
        /// @brief defines an invalid bf_reg_t
        bf_reg_t_invalid = static_cast<bsl::uint64>(BF_MAX_REG_T)
    };
}

#endif
