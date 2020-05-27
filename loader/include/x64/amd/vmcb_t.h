/**
 * @copyright
 * Copyright (C) 2020 Assured Information Security, Inc.
 *
 * @copyright
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * @copyright
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * @copyright
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef VMCB_H
#define VMCB_H

#pragma pack(push, 1)

#include <loader_types.h>

/**
 * @struct vmcb_t
 *
 * <!-- description -->
 *   @brief The following defines the structure of the VMCB used by AMD's
 *     hypervisor extensions. Note that this is designed to consume a page
 *     in memory, even if SEV is enabled (in which case a portion of this
 *     structure would never get used). For more information about this
 *     structure, please see the AMD SDM.
 *
 * <!-- notes -->
 *   @note AMD actually defines the VMCB using bit fields and provides
 *     access to the VMCB without the need for vmload/vmsave instructions.
 *     Intel on the other hand provides indexed access to the VMCS using
 *     the vmread/vmwrite instructions and the format of the structure is
 *     opaque, meaning you cannot directly modify it. To ensure that the
 *     implementation of the VMCB and the VMCS is similar, we provide
 *     the VMCB with names and will require extensions to mimic Intel,
 *     by attempting to read/write into this structure using a index and
 *     a vmread/vmwrite function, which is why our version of the VMCB
 *     has non-standard names as we had to logically group of the fields.
 */
struct vmcb_t
{
    // -------------------------------------------------------------------------
    // Control Area
    // -------------------------------------------------------------------------

    uint16_t intercept_cr_read;              ///< offset 0x0000
    uint16_t intercept_cr_write;             ///< offset 0x0002
    uint16_t intercept_dr_read;              ///< offset 0x0004
    uint16_t intercept_dr_write;             ///< offset 0x0006
    uint32_t intercept_exception;            ///< offset 0x0008
    uint64_t intercept_instruction1;         ///< offset 0x000C
    uint32_t intercept_instruction2;         ///< offset 0x0014
    uint8_t reserved1[0x24];                 ///< offset 0x0018
    uint16_t pause_filter_threshold;         ///< offset 0x003C
    uint16_t pause_filter_count;             ///< offset 0x003E
    uint64_t iopm_base_pa;                   ///< offset 0x0040
    uint64_t msrpm_base_pa;                  ///< offset 0x0048
    uint64_t tsc_offset;                     ///< offset 0x0050
    uint32_t guest_asid;                     ///< offset 0x0058
    uint8_t tlb_control;                     ///< offset 0x005C
    uint8_t reserved2[0x3];                  ///< offset 0x005D
    uint64_t virtual_interrupt_a;            ///< offset 0x0060
    uint64_t virtual_interrupt_b;            ///< offset 0x0068
    int64_t exitcode;                        ///< offset 0x0070
    uint64_t exitinfo1;                      ///< offset 0x0078
    uint64_t exitinfo2;                      ///< offset 0x0080
    uint64_t exitininfo;                     ///< offset 0x0088
    uint64_t ctls1;                          ///< offset 0x0090
    uint64_t avic_apic_bar;                  ///< offset 0x0098
    uint64_t guest_pa_of_ghcb;               ///< offset 0x00A0
    uint64_t eventinj;                       ///< offset 0x00A8
    uint64_t n_cr3;                          ///< offset 0x00B0
    uint64_t ctls2;                          ///< offset 0x00B8
    uint32_t vmcb_clean_bits;                ///< offset 0x00C0
    uint8_t reserved3[0x4];                  ///< offset 0x00C4
    uint64_t nrip;                           ///< offset 0x00C8
    uint8_t number_of_bytes_fetched;         ///< offset 0x00D0
    uint8_t guest_instruction_bytes[0xF];    ///< offset 0x00D1
    uint64_t avic_apic_backing_page_ptr;     ///< offset 0x00E0
    uint8_t reserved4[0x8];                  ///< offset 0x00E8
    uint64_t avic_logical_table_ptr;         ///< offset 0x00F0
    uint64_t avic_physical_table_ptr;        ///< offset 0x00F8
    uint8_t reserved5[0x8];                  ///< offset 0x0100
    uint64_t vmsa_ptr;                       ///< offset 0x0108
    uint8_t reserved6[0x2F0];                ///< offset 0x0110

    // -------------------------------------------------------------------------
    // State Save Area
    // -------------------------------------------------------------------------

    uint16_t es_selector;         ///< offset 0x0400
    uint16_t es_attrib;           ///< offset 0x0402
    uint32_t es_limit;            ///< offset 0x0404
    uint64_t es_base;             ///< offset 0x0408
    uint16_t cs_selector;         ///< offset 0x0410
    uint16_t cs_attrib;           ///< offset 0x0412
    uint32_t cs_limit;            ///< offset 0x0414
    uint64_t cs_base;             ///< offset 0x0418
    uint16_t ss_selector;         ///< offset 0x0420
    uint16_t ss_attrib;           ///< offset 0x0422
    uint32_t ss_limit;            ///< offset 0x0424
    uint64_t ss_base;             ///< offset 0x0428
    uint16_t ds_selector;         ///< offset 0x0430
    uint16_t ds_attrib;           ///< offset 0x0432
    uint32_t ds_limit;            ///< offset 0x0434
    uint64_t ds_base;             ///< offset 0x0438
    uint16_t fs_selector;         ///< offset 0x0440
    uint16_t fs_attrib;           ///< offset 0x0442
    uint32_t fs_limit;            ///< offset 0x0444
    uint64_t fs_base;             ///< offset 0x0448
    uint16_t gs_selector;         ///< offset 0x0450
    uint16_t gs_attrib;           ///< offset 0x0452
    uint32_t gs_limit;            ///< offset 0x0454
    uint64_t gs_base;             ///< offset 0x0458
    uint16_t gdtr_selector;       ///< offset 0x0460
    uint16_t gdtr_attrib;         ///< offset 0x0462
    uint32_t gdtr_limit;          ///< offset 0x0464
    uint64_t gdtr_base;           ///< offset 0x0468
    uint16_t ldtr_selector;       ///< offset 0x0470
    uint16_t ldtr_attrib;         ///< offset 0x0472
    uint32_t ldtr_limit;          ///< offset 0x0474
    uint64_t ldtr_base;           ///< offset 0x0478
    uint16_t idtr_selector;       ///< offset 0x0480
    uint16_t idtr_attrib;         ///< offset 0x0482
    uint32_t idtr_limit;          ///< offset 0x0484
    uint64_t idtr_base;           ///< offset 0x0488
    uint16_t tr_selector;         ///< offset 0x0490
    uint16_t tr_attrib;           ///< offset 0x0492
    uint32_t tr_limit;            ///< offset 0x0494
    uint64_t tr_base;             ///< offset 0x0498
    uint8_t reserved7[0x2B];      ///< offset 0x04A0
    uint8_t cpl;                  ///< offset 0x04CB
    uint8_t reserved8[0x4];       ///< offset 0x04CC
    uint64_t efer;                ///< offset 0x04D0
    uint8_t reserved9[0x70];      ///< offset 0x04D8
    uint64_t cr4;                 ///< offset 0x0548
    uint64_t cr3;                 ///< offset 0x0550
    uint64_t cr0;                 ///< offset 0x0558
    uint64_t dr7;                 ///< offset 0x0560
    uint64_t dr6;                 ///< offset 0x0568
    uint64_t rflags;              ///< offset 0x0570
    uint64_t rip;                 ///< offset 0x0578
    uint8_t reserved10[0x58];     ///< offset 0x0580
    uint64_t rsp;                 ///< offset 0x05D8
    uint8_t reserved11[0x18];     ///< offset 0x05E0
    uint64_t rax;                 ///< offset 0x05F8
    uint64_t star;                ///< offset 0x0600
    uint64_t lstar;               ///< offset 0x0608
    uint64_t cstar;               ///< offset 0x0610
    uint64_t sfmask;              ///< offset 0x0618
    uint64_t kernel_gs_base;      ///< offset 0x0620
    uint64_t sysenter_cs;         ///< offset 0x0628
    uint64_t sysenter_esp;        ///< offset 0x0630
    uint64_t sysenter_eip;        ///< offset 0x0638
    uint64_t cr2;                 ///< offset 0x0640
    uint8_t reserved12[0x20];     ///< offset 0x0648
    uint64_t g_pat;               ///< offset 0x0668
    uint64_t dbgctl;              ///< offset 0x0670
    uint64_t br_from;             ///< offset 0x0678
    uint64_t br_to;               ///< offset 0x0680
    uint64_t lastexcpfrom;        ///< offset 0x0688
    uint64_t lastexcpto;          ///< offset 0x0690
    uint8_t reserved13[0x968];    ///< offset 0x0698
};

_Static_assert(sizeof(struct vmcb_t) == 0x1000, "");

// -----------------------------------------------------------------------------
// Intercept Bit Masks
// -----------------------------------------------------------------------------

#define VMCB_INTERCEPT_INSTRUCTION1_INTR ((uint64_t)1U << 0U)
#define VMCB_INTERCEPT_INSTRUCTION1_NMI ((uint64_t)1U << 1U)
#define VMCB_INTERCEPT_INSTRUCTION1_SMI ((uint64_t)1U << 2U)
#define VMCB_INTERCEPT_INSTRUCTION1_INIT ((uint64_t)1U << 3U)
#define VMCB_INTERCEPT_INSTRUCTION1_VINTR ((uint64_t)1U << 4U)
#define VMCB_INTERCEPT_INSTRUCTION1_CR0 ((uint64_t)1U << 5U)
#define VMCB_INTERCEPT_INSTRUCTION1_READ_IDTR ((uint64_t)1U << 6U)
#define VMCB_INTERCEPT_INSTRUCTION1_READ_GDTR ((uint64_t)1U << 7U)
#define VMCB_INTERCEPT_INSTRUCTION1_READ_LDTR ((uint64_t)1U << 8U)
#define VMCB_INTERCEPT_INSTRUCTION1_READ_TR ((uint64_t)1U << 9U)
#define VMCB_INTERCEPT_INSTRUCTION1_WRITE_IDTR ((uint64_t)1U << 10U)
#define VMCB_INTERCEPT_INSTRUCTION1_WRITE_GDTR ((uint64_t)1U << 11U)
#define VMCB_INTERCEPT_INSTRUCTION1_WRITE_LDTR ((uint64_t)1U << 12U)
#define VMCB_INTERCEPT_INSTRUCTION1_WRITE_TR ((uint64_t)1U << 13U)
#define VMCB_INTERCEPT_INSTRUCTION1_RDTSC ((uint64_t)1U << 14U)
#define VMCB_INTERCEPT_INSTRUCTION1_RDPMC ((uint64_t)1U << 15U)
#define VMCB_INTERCEPT_INSTRUCTION1_PUSHF ((uint64_t)1U << 16U)
#define VMCB_INTERCEPT_INSTRUCTION1_POPF ((uint64_t)1U << 17U)
#define VMCB_INTERCEPT_INSTRUCTION1_CPUID ((uint64_t)1U << 18U)
#define VMCB_INTERCEPT_INSTRUCTION1_RSM ((uint64_t)1U << 19U)
#define VMCB_INTERCEPT_INSTRUCTION1_IRET ((uint64_t)1U << 20U)
#define VMCB_INTERCEPT_INSTRUCTION1_INTn ((uint64_t)1U << 21U)
#define VMCB_INTERCEPT_INSTRUCTION1_INVD ((uint64_t)1U << 22U)
#define VMCB_INTERCEPT_INSTRUCTION1_PAUSE ((uint64_t)1U << 23U)
#define VMCB_INTERCEPT_INSTRUCTION1_HLT ((uint64_t)1U << 24U)
#define VMCB_INTERCEPT_INSTRUCTION1_INVLPG ((uint64_t)1U << 25U)
#define VMCB_INTERCEPT_INSTRUCTION1_INVLPGA ((uint64_t)1U << 26U)
#define VMCB_INTERCEPT_INSTRUCTION1_IOIO_PROT ((uint64_t)1U << 27U)
#define VMCB_INTERCEPT_INSTRUCTION1_MSR_PROT ((uint64_t)1U << 28U)
#define VMCB_INTERCEPT_INSTRUCTION1_TASK_SWITCH ((uint64_t)1U << 29U)
#define VMCB_INTERCEPT_INSTRUCTION1_FERR_FREEZE ((uint64_t)1U << 30U)
#define VMCB_INTERCEPT_INSTRUCTION1_SHUTDOWN ((uint64_t)1U << 31U)
#define VMCB_INTERCEPT_INSTRUCTION1_VMRUN ((uint64_t)1U << 32U)
#define VMCB_INTERCEPT_INSTRUCTION1_VMMCALL ((uint64_t)1U << 33U)
#define VMCB_INTERCEPT_INSTRUCTION1_VMLOAD ((uint64_t)1U << 34U)
#define VMCB_INTERCEPT_INSTRUCTION1_VMSAVE ((uint64_t)1U << 35U)
#define VMCB_INTERCEPT_INSTRUCTION1_STGI ((uint64_t)1U << 36U)
#define VMCB_INTERCEPT_INSTRUCTION1_CLGI ((uint64_t)1U << 37U)
#define VMCB_INTERCEPT_INSTRUCTION1_SKINIT ((uint64_t)1U << 38U)
#define VMCB_INTERCEPT_INSTRUCTION1_RDTSCP ((uint64_t)1U << 39U)
#define VMCB_INTERCEPT_INSTRUCTION1_ICEBP ((uint64_t)1U << 40U)
#define VMCB_INTERCEPT_INSTRUCTION1_WBINVD ((uint64_t)1U << 41U)
#define VMCB_INTERCEPT_INSTRUCTION1_MONITOR ((uint64_t)1U << 42U)
#define VMCB_INTERCEPT_INSTRUCTION1_MWAIT_UNCONDITIONAL ((uint64_t)1U << 43U)
#define VMCB_INTERCEPT_INSTRUCTION1_MWAIT_ARMED ((uint64_t)1U << 44U)
#define VMCB_INTERCEPT_INSTRUCTION1_XSETBV ((uint64_t)1U << 45U)
#define VMCB_INTERCEPT_INSTRUCTION1_RDPRU ((uint64_t)1U << 46U)
#define VMCB_INTERCEPT_INSTRUCTION1_EFER_WRITE_COMPLETED ((uint64_t)1U << 47U)
#define VMCB_INTERCEPT_INSTRUCTION1_CR0_WRITE_COMPLETED ((uint64_t)1U << 48U)
#define VMCB_INTERCEPT_INSTRUCTION1_CR1_WRITE_COMPLETED ((uint64_t)1U << 49U)
#define VMCB_INTERCEPT_INSTRUCTION1_CR2_WRITE_COMPLETED ((uint64_t)1U << 50U)
#define VMCB_INTERCEPT_INSTRUCTION1_CR3_WRITE_COMPLETED ((uint64_t)1U << 51U)
#define VMCB_INTERCEPT_INSTRUCTION1_CR4_WRITE_COMPLETED ((uint64_t)1U << 52U)
#define VMCB_INTERCEPT_INSTRUCTION1_CR5_WRITE_COMPLETED ((uint64_t)1U << 53U)
#define VMCB_INTERCEPT_INSTRUCTION1_CR6_WRITE_COMPLETED ((uint64_t)1U << 54U)
#define VMCB_INTERCEPT_INSTRUCTION1_CR7_WRITE_COMPLETED ((uint64_t)1U << 55U)
#define VMCB_INTERCEPT_INSTRUCTION1_CR8_WRITE_COMPLETED ((uint64_t)1U << 56U)
#define VMCB_INTERCEPT_INSTRUCTION1_CR9_WRITE_COMPLETED ((uint64_t)1U << 57U)
#define VMCB_INTERCEPT_INSTRUCTION1_CR10_WRITE_COMPLETED ((uint64_t)1U << 58U)
#define VMCB_INTERCEPT_INSTRUCTION1_CR11_WRITE_COMPLETED ((uint64_t)1U << 59U)
#define VMCB_INTERCEPT_INSTRUCTION1_CR12_WRITE_COMPLETED ((uint64_t)1U << 60U)
#define VMCB_INTERCEPT_INSTRUCTION1_CR13_WRITE_COMPLETED ((uint64_t)1U << 61U)
#define VMCB_INTERCEPT_INSTRUCTION1_CR14_WRITE_COMPLETED ((uint64_t)1U << 62U)
#define VMCB_INTERCEPT_INSTRUCTION1_CR15_WRITE_COMPLETED ((uint64_t)1U << 63U)

// -----------------------------------------------------------------------------
// VMEXIT Code
// -----------------------------------------------------------------------------

#define VMEXIT_CPUID ((int64_t)0x072)
#define VMEXIT_VMRUN ((int64_t)0x080)
#define VMEXIT_VMMCALL ((int64_t)0x081)
#define VMEXIT_INVALID ((int64_t)-1)

#pragma pack(pop)

#endif
