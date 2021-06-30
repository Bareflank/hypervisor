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
        bf_reg_t_rax = (0_u64).get(),
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
        /// @brief defines the rip register
        bf_reg_t_rip = (15_u64).get(),
        /// @brief defines the rsp register
        bf_reg_t_rsp = (16_u64).get(),
        /// @brief defines the rflags register
        bf_reg_t_rflags = (17_u64).get(),
        /// @brief defines the gdtr_base_addr register
        bf_reg_t_gdtr_base_addr = (18_u64).get(),
        /// @brief defines the gdtr_limit register
        bf_reg_t_gdtr_limit = (19_u64).get(),
        /// @brief defines the idtr_base_addr register
        bf_reg_t_idtr_base_addr = (20_u64).get(),
        /// @brief defines the idtr_limit register
        bf_reg_t_idtr_limit = (21_u64).get(),
        /// @brief defines the es register
        bf_reg_t_es = (22_u64).get(),
        /// @brief defines the es_base_addr register
        bf_reg_t_es_base_addr = (23_u64).get(),
        /// @brief defines the es_limit register
        bf_reg_t_es_limit = (24_u64).get(),
        /// @brief defines the es_attributes register
        bf_reg_t_es_attributes = (25_u64).get(),
        /// @brief defines the cs register
        bf_reg_t_cs = (26_u64).get(),
        /// @brief defines the cs_base_addr register
        bf_reg_t_cs_base_addr = (27_u64).get(),
        /// @brief defines the cs_limit register
        bf_reg_t_cs_limit = (28_u64).get(),
        /// @brief defines the cs_attributes register
        bf_reg_t_cs_attributes = (29_u64).get(),
        /// @brief defines the ss register
        bf_reg_t_ss = (30_u64).get(),
        /// @brief defines the ss_base_addr register
        bf_reg_t_ss_base_addr = (31_u64).get(),
        /// @brief defines the ss_limit register
        bf_reg_t_ss_limit = (32_u64).get(),
        /// @brief defines the ss_attributes register
        bf_reg_t_ss_attributes = (33_u64).get(),
        /// @brief defines the ds register
        bf_reg_t_ds = (34_u64).get(),
        /// @brief defines the ds_base_addr register
        bf_reg_t_ds_base_addr = (35_u64).get(),
        /// @brief defines the ds_limit register
        bf_reg_t_ds_limit = (36_u64).get(),
        /// @brief defines the ds_attributes register
        bf_reg_t_ds_attributes = (37_u64).get(),
        /// @brief defines the fs register
        bf_reg_t_fs = (38_u64).get(),
        /// @brief defines the fs_base_addr register
        bf_reg_t_fs_base_addr = (39_u64).get(),
        /// @brief defines the fs_limit register
        bf_reg_t_fs_limit = (40_u64).get(),
        /// @brief defines the fs_attributes register
        bf_reg_t_fs_attributes = (41_u64).get(),
        /// @brief defines the gs register
        bf_reg_t_gs = (42_u64).get(),
        /// @brief defines the gs_base_addr register
        bf_reg_t_gs_base_addr = (43_u64).get(),
        /// @brief defines the gs_limit register
        bf_reg_t_gs_limit = (44_u64).get(),
        /// @brief defines the gs_attributes register
        bf_reg_t_gs_attributes = (45_u64).get(),
        /// @brief defines the ldtr register
        bf_reg_t_ldtr = (46_u64).get(),
        /// @brief defines the ldtr_base_addr register
        // We don't have a choice in the naming here
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        bf_reg_t_ldtr_base_addr = (47_u64).get(),
        /// @brief defines the ldtr_limit register
        // We don't have a choice in the naming here
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        bf_reg_t_ldtr_limit = (48_u64).get(),
        /// @brief defines the ldtr_attributes register
        bf_reg_t_ldtr_attributes = (49_u64).get(),
        /// @brief defines the tr register
        bf_reg_t_tr = (50_u64).get(),
        /// @brief defines the tr_base_addr register
        bf_reg_t_tr_base_addr = (51_u64).get(),
        /// @brief defines the tr_limit register
        bf_reg_t_tr_limit = (52_u64).get(),
        /// @brief defines the tr_attributes register
        bf_reg_t_tr_attributes = (53_u64).get(),
        /// @brief defines the cr0 register
        bf_reg_t_cr0 = (54_u64).get(),
        /// @brief defines the cr2 register
        bf_reg_t_cr2 = (55_u64).get(),
        /// @brief defines the cr3 register
        bf_reg_t_cr3 = (56_u64).get(),
        /// @brief defines the cr4 register
        bf_reg_t_cr4 = (57_u64).get(),
        /// @brief defines the dr6 register
        bf_reg_t_dr6 = (58_u64).get(),
        /// @brief defines the dr7 register
        bf_reg_t_dr7 = (59_u64).get(),
        /// @brief defines the ia32_efer register
        bf_reg_t_ia32_efer = (60_u64).get(),
        /// @brief defines the ia32_star register
        bf_reg_t_ia32_star = (61_u64).get(),
        /// @brief defines the ia32_lstar register
        bf_reg_t_ia32_lstar = (62_u64).get(),
        /// @brief defines the ia32_cstar register
        bf_reg_t_ia32_cstar = (63_u64).get(),
        /// @brief defines the ia32_fmask register
        bf_reg_t_ia32_fmask = (64_u64).get(),
        /// @brief defines the ia32_fs_base register
        bf_reg_t_ia32_fs_base = (65_u64).get(),
        /// @brief defines the ia32_gs_base register
        bf_reg_t_ia32_gs_base = (66_u64).get(),
        /// @brief defines the ia32_kernel_gs_base register
        bf_reg_t_ia32_kernel_gs_base = (67_u64).get(),
        /// @brief defines the ia32_sysenter_cs register
        bf_reg_t_ia32_sysenter_cs = (68_u64).get(),
        /// @brief defines the ia32_sysenter_esp register
        bf_reg_t_ia32_sysenter_esp = (69_u64).get(),
        /// @brief defines the ia32_sysenter_eip register
        bf_reg_t_ia32_sysenter_eip = (70_u64).get(),
        /// @brief defines the ia32_pat register
        bf_reg_t_ia32_pat = (71_u64).get(),
        /// @brief defines the ia32_debugctl register
        bf_reg_t_ia32_debugctl = (72_u64).get(),
    };
}

#endif
