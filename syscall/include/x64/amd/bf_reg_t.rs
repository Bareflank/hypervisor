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

/// @brief defines the rbx register
const BF_REG_T_RBX:u64 = 1;
/// @brief defines the rcx register
const BF_REG_T_RCX:u64 = 2;
/// @brief defines the rdx register
const BF_REG_T_RDX:u64 = 3;
/// @brief defines the rbp register
const BF_REG_T_RBP:u64 = 4;
/// @brief defines the rsi register
const BF_REG_T_RSI:u64 = 5;
/// @brief defines the rdi register
const BF_REG_T_RDI:u64 = 6;
/// @brief defines the r8 register
const BF_REG_T_R8:u64 = 7;
/// @brief defines the r9 register
const BF_REG_T_R9:u64 = 8;
/// @brief defines the r10 register
const BF_REG_T_R10:u64 = 9;
/// @brief defines the r11 register
const BF_REG_T_R11:u64 = 10;
/// @brief defines the r12 register
const BF_REG_T_R12:u64 = 11;
/// @brief defines the r13 register
const BF_REG_T_R13:u64 = 12;
/// @brief defines the r14 register
const BF_REG_T_R14:u64 = 13;
/// @brief defines the r15 register
const BF_REG_T_R15:u64 = 14;
/// @brief defines the intercept_cr_read register in the VMCB
const BF_REG_T_INTERCEPT_CR_READ:u64 = 15;
/// @brief defines the intercept_cr_write register in the VMCB
const BF_REG_T_INTERCEPT_CR_WRITE:u64 = 16;
/// @brief defines the intercept_dr_read register in the VMCB
const BF_REG_T_INTERCEPT_DR_READ:u64 = 17;
/// @brief defines the intercept_dr_write register in the VMCB
const BF_REG_T_INTERCEPT_DR_WRITE:u64 = 18;
/// @brief defines the intercept_exception register in the VMCB
const BF_REG_T_INTERCEPT_EXCEPTION:u64 = 19;
/// @brief defines the intercept_instruction1 register in the VMCB
const BF_REG_T_INTERCEPT_INSTRUCTION1:u64 = 20;
/// @brief defines the intercept_instruction2 register in the VMCB
const BF_REG_T_INTERCEPT_INSTRUCTION2:u64 = 21;
/// @brief defines the intercept_instruction3 register in the VMCB
const BF_REG_T_INTERCEPT_INSTRUCTION3:u64 = 22;
/// @brief defines the pause_filter_threshold register in the VMCB
const BF_REG_T_PAUSE_FILTER_THRESHOLD:u64 = 23;
/// @brief defines the pause_filter_count register in the VMCB
const BF_REG_T_PAUSE_FILTER_COUNT:u64 = 24;
/// @brief defines the iopm_base_pa register in the VMCB
const BF_REG_T_IOPM_BASE_PA:u64 = 25;
/// @brief defines the msrpm_base_pa register in the VMCB
const BF_REG_T_MSRPM_BASE_PA:u64 = 26;
/// @brief defines the tsc_offset register in the VMCB
const BF_REG_T_TSC_OFFSET:u64 = 27;
/// @brief defines the guest_asid register in the VMCB
const BF_REG_T_GUEST_ASID:u64 = 28;
/// @brief defines the tlb_control register in the VMCB
const BF_REG_T_TLB_CONTROL:u64 = 29;
/// @brief defines the virtual_interrupt_a register in the VMCB
const BF_REG_T_VIRTUAL_INTERRUPT_A:u64 = 30;
/// @brief defines the virtual_interrupt_b register in the VMCB
const BF_REG_T_VIRTUAL_INTERRUPT_B:u64 = 31;
/// @brief defines the exitcode register in the VMCB
const BF_REG_T_EXITCODE:u64 = 32;
/// @brief defines the exitinfo1 register in the VMCB
const BF_REG_T_EXITINFO1:u64 = 33;
/// @brief defines the exitinfo2 register in the VMCB
const BF_REG_T_EXITINFO2:u64 = 34;
/// @brief defines the exitininfo register in the VMCB
const BF_REG_T_EXITININFO:u64 = 35;
/// @brief defines the ctls1 register in the VMCB
const BF_REG_T_CTLS1:u64 = 36;
/// @brief defines the avic_apic_bar register in the VMCB
const BF_REG_T_AVIC_APIC_BAR:u64 = 37;
/// @brief defines the guest_pa_of_ghcb register in the VMCB
const BF_REG_T_GUEST_PA_OF_GHCB:u64 = 38;
/// @brief defines the eventinj register in the VMCB
const BF_REG_T_EVENTINJ:u64 = 39;
/// @brief defines the n_cr3 register in the VMCB
const BF_REG_T_N_CR3:u64 = 40;
/// @brief defines the ctls2 register in the VMCB
const BF_REG_T_CTLS2:u64 = 41;
/// @brief defines the vmcb_clean_bits register in the VMCB
const BF_REG_T_VMCB_CLEAN_BITS:u64 = 42;
/// @brief defines the nrip register in the VMCB
const BF_REG_T_NRIP:u64 = 43;
/// @brief defines the number_of_bytes_fetched register in the VMCB
const BF_REG_T_NUMBER_OF_BYTES_FETCHED:u64 = 44;
/// @brief defines the avic_apic_backing_page_ptr register in the VMCB
const BF_REG_T_AVIC_APIC_BACKING_PAGE_PTR:u64 = 45;
/// @brief defines the avic_logical_table_ptr register in the VMCB
const BF_REG_T_AVIC_LOGICAL_TABLE_PTR:u64 = 46;
/// @brief defines the avic_physical_table_ptr register in the VMCB
const BF_REG_T_AVIC_PHYSICAL_TABLE_PTR:u64 = 47;
/// @brief defines the vmsa_ptr register in the VMCB
const BF_REG_T_VMSA_PTR:u64 = 48;
/// @brief defines the es_selector register in the VMCB
const BF_REG_T_ES_SELECTOR:u64 = 49;
/// @brief defines the es_attrib register in the VMCB
const BF_REG_T_ES_ATTRIB:u64 = 50;
/// @brief defines the es_limit register in the VMCB
const BF_REG_T_ES_LIMIT:u64 = 51;
/// @brief defines the es_base register in the VMCB
const BF_REG_T_ES_BASE:u64 = 52;
/// @brief defines the cs_selector register in the VMCB
const BF_REG_T_CS_SELECTOR:u64 = 53;
/// @brief defines the cs_attrib register in the VMCB
const BF_REG_T_CS_ATTRIB:u64 = 54;
/// @brief defines the cs_limit register in the VMCB
const BF_REG_T_CS_LIMIT:u64 = 55;
/// @brief defines the cs_base register in the VMCB
const BF_REG_T_CS_BASE:u64 = 56;
/// @brief defines the ss_selector register in the VMCB
const BF_REG_T_SS_SELECTOR:u64 = 57;
/// @brief defines the ss_attrib register in the VMCB
const BF_REG_T_SS_ATTRIB:u64 = 58;
/// @brief defines the ss_limit register in the VMCB
const BF_REG_T_SS_LIMIT:u64 = 59;
/// @brief defines the ss_base register in the VMCB
const BF_REG_T_SS_BASE:u64 = 60;
/// @brief defines the ds_selector register in the VMCB
const BF_REG_T_DS_SELECTOR:u64 = 61;
/// @brief defines the ds_attrib register in the VMCB
const BF_REG_T_DS_ATTRIB:u64 = 62;
/// @brief defines the ds_limit register in the VMCB
const BF_REG_T_DS_LIMIT:u64 = 63;
/// @brief defines the ds_base register in the VMCB
const BF_REG_T_DS_BASE:u64 = 64;
/// @brief defines the fs_selector register in the VMCB
const BF_REG_T_FS_SELECTOR:u64 = 65;
/// @brief defines the fs_attrib register in the VMCB
const BF_REG_T_FS_ATTRIB:u64 = 66;
/// @brief defines the fs_limit register in the VMCB
const BF_REG_T_FS_LIMIT:u64 = 67;
/// @brief defines the fs_base register in the VMCB
const BF_REG_T_FS_BASE:u64 = 68;
/// @brief defines the gs_selector register in the VMCB
const BF_REG_T_GS_SELECTOR:u64 = 69;
/// @brief defines the gs_attrib register in the VMCB
const BF_REG_T_GS_ATTRIB:u64 = 70;
/// @brief defines the gs_limit register in the VMCB
const BF_REG_T_GS_LIMIT:u64 = 71;
/// @brief defines the gs_base register in the VMCB
const BF_REG_T_GS_BASE:u64 = 72;
/// @brief defines the gdtr_selector register in the VMCB
const BF_REG_T_GDTR_SELECTOR:u64 = 73;
/// @brief defines the gdtr_attrib register in the VMCB
const BF_REG_T_GDTR_ATTRIB:u64 = 74;
/// @brief defines the gdtr_limit register in the VMCB
const BF_REG_T_GDTR_LIMIT:u64 = 75;
/// @brief defines the gdtr_base register in the VMCB
const BF_REG_T_GDTR_BASE:u64 = 76;
/// @brief defines the ldtr_selector register in the VMCB
const BF_REG_T_LDTR_SELECTOR:u64 = 77;
/// @brief defines the ldtr_attrib register in the VMCB
const BF_REG_T_LDTR_ATTRIB:u64 = 78;
/// @brief defines the ldtr_limit register in the VMCB
const BF_REG_T_LDTR_LIMIT:u64 = 79;
/// @brief defines the ldtr_base register in the VMCB
const BF_REG_T_LDTR_BASE:u64 = 80;
/// @brief defines the idtr_selector register in the VMCB
const BF_REG_T_IDTR_SELECTOR:u64 = 81;
/// @brief defines the idtr_attrib register in the VMCB
const BF_REG_T_IDTR_ATTRIB:u64 = 82;
/// @brief defines the idtr_limit register in the VMCB
const BF_REG_T_IDTR_LIMIT:u64 = 83;
/// @brief defines the idtr_base register in the VMCB
const BF_REG_T_IDTR_BASE:u64 = 84;
/// @brief defines the tr_selector register in the VMCB
const BF_REG_T_TR_SELECTOR:u64 = 85;
/// @brief defines the tr_attrib register in the VMCB
const BF_REG_T_TR_ATTRIB:u64 = 86;
/// @brief defines the tr_limit register in the VMCB
const BF_REG_T_TR_LIMIT:u64 = 87;
/// @brief defines the tr_base register in the VMCB
const BF_REG_T_TR_BASE:u64 = 88;
/// @brief defines the cpl register in the VMCB
const BF_REG_T_CPL:u64 = 89;
/// @brief defines the efer register in the VMCB
const BF_REG_T_EFER:u64 = 90;
/// @brief defines the cr4 register in the VMCB
const BF_REG_T_CR4:u64 = 91;
/// @brief defines the cr3 register in the VMCB
const BF_REG_T_CR3:u64 = 92;
/// @brief defines the cr0 register in the VMCB
const BF_REG_T_CR0:u64 = 93;
/// @brief defines the dr7 register in the VMCB
const BF_REG_T_DR7:u64 = 94;
/// @brief defines the dr6 register in the VMCB
const BF_REG_T_DR6:u64 = 95;
/// @brief defines the rflags register in the VMCB
const BF_REG_T_RFLAGS:u64 = 96;
/// @brief defines the rip register in the VMCB
const BF_REG_T_RIP:u64 = 97;
/// @brief defines the rsp register in the VMCB
const BF_REG_T_RSP:u64 = 98;
/// @brief defines the rax register in the VMCB
const BF_REG_T_RAX:u64 = 99;
/// @brief defines the star register in the VMCB
const BF_REG_T_STAR:u64 = 100;
/// @brief defines the lstar register in the VMCB
const BF_REG_T_LSTAR:u64 = 101;
/// @brief defines the cstar register in the VMCB
const BF_REG_T_CSTAR:u64 = 102;
/// @brief defines the sfmask register in the VMCB
const BF_REG_T_SFMASK:u64 = 103;
/// @brief defines the kernel_gs_base register in the VMCB
const BF_REG_T_KERNEL_GS_BASE:u64 = 104;
/// @brief defines the sysenter_cs register in the VMCB
const BF_REG_T_SYSENTER_CS:u64 = 105;
/// @brief defines the sysenter_esp register in the VMCB
const BF_REG_T_SYSENTER_ESP:u64 = 106;
/// @brief defines the sysenter_eip register in the VMCB
const BF_REG_T_SYSENTER_EIP:u64 = 107;
/// @brief defines the cr2 register in the VMCB
const BF_REG_T_CR2:u64 = 108;
/// @brief defines the g_pat register in the VMCB
const BF_REG_T_G_PAT:u64 = 109;
/// @brief defines the dbgctl register in the VMCB
const BF_REG_T_DBGCTL:u64 = 110;
/// @brief defines the br_from register in the VMCB
const BF_REG_T_BR_FROM:u64 = 112;
/// @brief defines the br_to register in the VMCB
const BF_REG_T_BR_TO:u64 = 113;
/// @brief defines the lastexcpfrom register in the VMCB
const BF_REG_T_LASTEXCPFROM:u64 = 114;
/// @brief defines the lastexcpto register in the VMCB
const BF_REG_T_LASTEXCPTO:u64 = 115;
