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

#ifndef STATE_SAVE_T_H
#define STATE_SAVE_T_H

#include "global_descriptor_table_register_t.h"
#include "interrupt_descriptor_table_register_t.h"
#include "tss_t.h"

#include <static_assert.h>
#include <types.h>

#pragma pack(push, 1)

/**
 * @struct state_save_t
 *
 * <!-- description -->
 *   @brief Stores state information for both Intel and AMD. Specifically,
 *     for a field to be included in this list, it must:
 *     - Be saved/restored by the VMCS/VMCB, meaning HVE will touch the field
 *       either because we don't have a choice, or because we enable HVE
 *       to do so (example being EFER and PAT on Intel)
 *     - Because the Microkernel needs it's own version of the field.
 *
 *     This list provides the set of all registers that meet the criteria
 *     above. It should be noted that this is the common set of fields
 *     for both Intel and AMD. To ensure consistency, the Microkernel will
 *     save/restore these fields on every VMExit/VMEntry. This ensures
 *     extensions can use this list of fields as documentation as to which
 *     fields it will have to deal with on its own.
 */
struct state_save_t
{
    /**************************************************************************/
    /* General Purpose Registers                                              */
    /**************************************************************************/

    /** @brief stores the value of rax (0x000) */
    uint64_t rax;
    /** @brief stores the value of rbx (0x008) */
    uint64_t rbx;
    /** @brief stores the value of rcx (0x010) */
    uint64_t rcx;
    /** @brief stores the value of rdx (0x018) */
    uint64_t rdx;
    /** @brief stores the value of rbp (0x020) */
    uint64_t rbp;
    /** @brief stores the value of rsi (0x028) */
    uint64_t rsi;
    /** @brief stores the value of rdi (0x030) */
    uint64_t rdi;
    /** @brief stores the value of r8 (0x038) */
    uint64_t r8;
    /** @brief stores the value of r9 (0x040) */
    uint64_t r9;
    /** @brief stores the value of r10 (0x048) */
    uint64_t r10;
    /** @brief stores the value of r11 (0x050) */
    uint64_t r11;
    /** @brief stores the value of r12 (0x058) */
    uint64_t r12;
    /** @brief stores the value of r13 (0x060) */
    uint64_t r13;
    /** @brief stores the value of r14 (0x068) */
    uint64_t r14;
    /** @brief stores the value of r15 (0x070) */
    uint64_t r15;
    /** @brief stores the value of rip (0x078) */
    uint64_t rip;
    /** @brief stores the value of rsp (0x080) */
    uint64_t rsp;

    /**************************************************************************/
    /* Flags                                                                  */
    /**************************************************************************/

    /** @brief stores the value of rflags (0x088) */
    uint64_t rflags;

    /**************************************************************************/
    /* Task-State Segment                                                     */
    /**************************************************************************/

    /** @brief stores a pointer to the tss (0x090) */
    struct tss_t *tss;

    /** @brief stores a pointer to the ist #1 */
    void *ist;

    /**************************************************************************/
    /* Descriptor Table Information                                           */
    /**************************************************************************/

    /** @brief stores the value of the GDTR (0x0A0) */
    struct global_descriptor_table_register_t gdtr;

    /** @brief added padding for alignment (0x0AA) */
    uint8_t pad1[0x6];

    /** @brief stores the value of the IDTR (0x0B0) */
    struct interrupt_descriptor_table_register_t idtr;

    /** @brief added padding for alignment (0x0BA) */
    uint8_t pad2[0x6];

    /** @brief stores the value of the ES segment selector (0x0C0) */
    uint16_t es_selector;
    /** @brief stores the value of the ES segment attributes (0x0C2) */
    uint16_t es_attrib;
    /** @brief stores the value of the ES segment limit (0x0C4) */
    uint32_t es_limit;
    /** @brief stores the value of the ES segment base (0x0C8) */
    uint64_t es_base;

    /** @brief stores the value of the CS segment selector (0x0D0) */
    uint16_t cs_selector;
    /** @brief stores the value of the CS segment attributes (0x0D2) */
    uint16_t cs_attrib;
    /** @brief stores the value of the CS segment limit (0x0D4) */
    uint32_t cs_limit;
    /** @brief stores the value of the CS segment base (0x0D8) */
    uint64_t cs_base;

    /** @brief stores the value of the SS segment selector (0x0E0) */
    uint16_t ss_selector;
    /** @brief stores the value of the SS segment attributes (0x0E2) */
    uint16_t ss_attrib;
    /** @brief stores the value of the SS segment limit (0x0E4) */
    uint32_t ss_limit;
    /** @brief stores the value of the SS segment base (0x0E8) */
    uint64_t ss_base;

    /** @brief stores the value of the DS segment selector (0x0F0) */
    uint16_t ds_selector;
    /** @brief stores the value of the DS segment attributes (0x0F2) */
    uint16_t ds_attrib;
    /** @brief stores the value of the DS segment limit (0x0F4) */
    uint32_t ds_limit;
    /** @brief stores the value of the DS segment base (0x0F8) */
    uint64_t ds_base;

    /** @brief stores the value of the FS segment selector (0x100) */
    uint16_t fs_selector;
    /** @brief stores the value of the FS segment attributes (0x102) */
    uint16_t fs_attrib;
    /** @brief stores the value of the FS segment limit (0x104) */
    uint32_t fs_limit;
    /** @brief stores the value of the FS segment base (0x108) */
    uint64_t fs_base;

    /** @brief stores the value of the GS segment selector (0x110) */
    uint16_t gs_selector;
    /** @brief stores the value of the GS segment attributes (0x112) */
    uint16_t gs_attrib;
    /** @brief stores the value of the GS segment limit (0x114) */
    uint32_t gs_limit;
    /** @brief stores the value of the GS segment base (0x118) */
    uint64_t gs_base;

    /** @brief stores the value of the LDTR segment selector (0x120) */
    uint16_t ldtr_selector;
    /** @brief stores the value of the LDTR segment attributes (0x122) */
    uint16_t ldtr_attrib;
    /** @brief stores the value of the LDTR segment limit (0x124) */
    uint32_t ldtr_limit;
    /** @brief stores the value of the LDTR segment base (0x128) */
    uint64_t ldtr_base;

    /** @brief stores the value of the TR segment selector (0x130) */
    uint16_t tr_selector;
    /** @brief stores the value of the TR segment attributes (0x132) */
    uint16_t tr_attrib;
    /** @brief stores the value of the TR segment limit (0x134) */
    uint32_t tr_limit;
    /** @brief stores the value of the TR segment base (0x138) */
    uint64_t tr_base;

    /**************************************************************************/
    /* Control Registers                                                      */
    /**************************************************************************/

    /** @brief stores the value of the CR0 control register (0x140) */
    uint64_t cr0;
    /** @brief stores reserved (0x148) */
    uint64_t reserved;
    /** @brief stores the value of the CR2 control register (0x150) */
    uint64_t cr2;
    /** @brief stores the value of the CR3 control register (0x158) */
    uint64_t cr3;
    /** @brief stores the value of the CR4 control register (0x160) */
    uint64_t cr4;

    /** @brief reserved for future use (0x168) */
    uint64_t reserved0[0xB];

    /**************************************************************************/
    /* Debug Registers                                                        */
    /**************************************************************************/

    /** @brief reserved for future use (0x1C0) */
    uint64_t reserved1[0x6];

    /** @brief stores the value of DR6 debug register (0x1F0) */
    uint64_t dr6;
    /** @brief stores the value of DR7 debug register (0x1F8) */
    uint64_t dr7;

    /** @brief reserved for future use (0x200) */
    uint64_t reserved2[0x8];

    /**************************************************************************/
    /* MSRs                                                                   */
    /**************************************************************************/

    /** @brief stores the value of the IA32_EFER MSR (0x240) */
    uint64_t ia32_efer;
    /** @brief stores the value of the IA32_STAR MSR (0x248) */
    uint64_t ia32_star;
    /** @brief stores the value of the IA32_LSTAR MSR (0x250) */
    uint64_t ia32_lstar;
    /** @brief stores the value of the IA32_CSTAR MSR (0x258) */
    uint64_t ia32_cstar;
    /** @brief stores the value of the IA32_FMASK MSR (0x260) */
    uint64_t ia32_fmask;
    /** @brief stores the value of the IA32_FS_BASE MSR (0x268) */
    uint64_t ia32_fs_base;
    /** @brief stores the value of the IA32_GS_BASE MSR (0x270) */
    uint64_t ia32_gs_base;
    /** @brief stores the value of the IA32_KERNEL_GS_BASE MSR (0x278) */
    uint64_t ia32_kernel_gs_base;
    /** @brief stores the value of the IA32_SYSENTER_CS MSR (0x280) */
    uint64_t ia32_sysenter_cs;
    /** @brief stores the value of the IA32_SYSENTER_ESP MSR (0x288) */
    uint64_t ia32_sysenter_esp;
    /** @brief stores the value of the IA32_SYSENTER_EIP MSR (0x290) */
    uint64_t ia32_sysenter_eip;
    /** @brief stores the value of the IA32_PAT MSR (0x298) */
    uint64_t ia32_pat;
    /** @brief stores the value of the IA32_DEBUGCTL MSR (0x2A0) */
    uint64_t ia32_debugctl;

    /** @brief reserved for future use (0x2A8) */
    uint64_t reserved3[0x7];

    /**************************************************************************/
    /* HVE Page                                                               */
    /**************************************************************************/

    /** @brief stores a pointer to the hve page (0x2E0) */
    void *hve_page;

    /**************************************************************************/
    /* Handlers                                                               */
    /**************************************************************************/

    /** @brief stores the promote handler (0x2E8) */
    void *promote_handler;
    /** @brief stores the esr default handler (0x2F0) */
    void *esr_default_handler;
    /** @brief stores the esr df handler (0x2F8) */
    void *esr_df_handler;
    /** @brief stores the esr gpf handler (0x300) */
    void *esr_gpf_handler;
    /** @brief stores the esr nmi handler (0x308) */
    void *esr_nmi_handler;
    /** @brief stores the esr pf handler (0x310) */
    void *esr_pf_handler;

    /**************************************************************************/
    /* NMI                                                                    */
    /**************************************************************************/

    /** @brief stores whether or not an NMI fired (0x318) */
    uint64_t nmi;

    /**************************************************************************/
    /* Map GDT                                                                */
    /**************************************************************************/

    /** @brief stores whether or not the GDT needs to be mapped (0x320) */
    uint64_t map_gdt;
};

/** @brief Check to make sure the state_save_t is the right size. */
STATIC_ASSERT(sizeof(struct state_save_t) == 0x328, invalid_size);

#pragma pack(pop)

#endif
