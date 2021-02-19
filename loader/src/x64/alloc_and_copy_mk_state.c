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

#include <bfelf_elf64_ehdr_t.h>
#include <constants.h>
#include <debug.h>
#include <disable_hve.h>
#include <enable_hve.h>
#include <esr_default.h>
#include <esr_df.h>
#include <esr_gpf.h>
#include <esr_nmi.h>
#include <esr_pf.h>
#include <intrinsic_rdmsr.h>
#include <intrinsic_scr0.h>
#include <intrinsic_scr4.h>
#include <platform.h>
#include <pml4t_t.h>
#include <set_gdt_descriptor.h>
#include <set_idt_descriptor.h>
#include <span_t.h>
#include <state_save_t.h>
#include <tss_t.h>
#include <types.h>

/** @brief defines the default value of rflags  */
#define RFLAGS ((uint64_t)0x2)

/** @brief defines the MSR_IA32_EFER MSR  */
#define MSR_IA32_EFER ((uint32_t)0xC0000080)

/** @brief defines the microkernel's CS selector */
#define MK_CS_SELECTOR ((uint16_t)0x10)
/** @brief defines the microkernel's CS attributes */
#define MK_CS_ATTRIB ((uint16_t)0x0000A09B)
/** @brief defines the microkernel's CS limit */
#define MK_CS_LIMIT ((uint32_t)0xFFFFFFFF)
/** @brief defines the microkernel's CS base */
#define MK_CS_BASE ((uint64_t)0x0)

/** @brief defines the microkernel's SS selector */
#define MK_SS_SELECTOR ((uint16_t)0x18)
/** @brief defines the microkernel's SS attributes */
#define MK_SS_ATTRIB ((uint16_t)0x0000C093)
/** @brief defines the microkernel's SS limit */
#define MK_SS_LIMIT ((uint32_t)0xFFFFFFFF)
/** @brief defines the microkernel's SS base */
#define MK_SS_BASE ((uint64_t)0x0)

/** @brief defines the microkernel's TR selector */
#define MK_TR_SELECTOR ((uint16_t)0x40)
/** @brief defines the microkernel's TR attributes */
#define MK_TR_ATTRIB ((uint16_t)0x00000089)
/** @brief defines the microkernel's TR limit */
#define MK_TR_LIMIT ((uint32_t)(sizeof(struct tss_t) - ((uint64_t)1)))
/** @brief defines the microkernel's TR base */
#define MK_TR_BASE ((uint64_t)0x0)

/** @brief defines the microkernel's CS selector */
#define EXT_CS_SELECTOR ((uint16_t)0x28)
/** @brief defines the microkernel's CS attributes */
#define EXT_CS_ATTRIB ((uint16_t)0x0000A0FB)
/** @brief defines the microkernel's CS limit */
#define EXT_CS_LIMIT ((uint32_t)0xFFFFFFFF)
/** @brief defines the microkernel's CS base */
#define EXT_CS_BASE ((uint64_t)0x0)

/** @brief defines the microkernel's SS selector */
#define EXT_SS_SELECTOR ((uint16_t)0x20)
/** @brief defines the microkernel's SS attributes */
#define EXT_SS_ATTRIB ((uint16_t)0x0000C0F3)
/** @brief defines the microkernel's SS limit */
#define EXT_SS_LIMIT ((uint32_t)0xFFFFFFFF)
/** @brief defines the microkernel's SS base */
#define EXT_SS_BASE ((uint64_t)0x0)

/** @brief defines the DIVIDE_BY_ZERO_ERROR_VECTOR ESR vector */
#define ESR_DIVIDE_BY_ZERO_ERROR_VECTOR ((uint32_t)0)
/** @brief defines the DEBUG_VECTOR ESR vector */
#define ESR_DEBUG_VECTOR ((uint32_t)1)
/** @brief defines the NON_MASKABLE_INTERRUPT_VECTOR ESR vector */
#define ESR_NON_MASKABLE_INTERRUPT_VECTOR ((uint32_t)2)
/** @brief defines the BREAKPOINT_VECTOR ESR vector */
#define ESR_BREAKPOINT_VECTOR ((uint32_t)3)
/** @brief defines the OVERFLOW_VECTOR ESR vector */
#define ESR_OVERFLOW_VECTOR ((uint32_t)4)
/** @brief defines the BOUND_RANGE_VECTOR ESR vector */
#define ESR_BOUND_RANGE_VECTOR ((uint32_t)5)
/** @brief defines the INVALID_OPCODE_VECTOR ESR vector */
#define ESR_INVALID_OPCODE_VECTOR ((uint32_t)6)
/** @brief defines the DEVICE_NOT_AVAILABLE_VECTOR ESR vector */
#define ESR_DEVICE_NOT_AVAILABLE_VECTOR ((uint32_t)7)
/** @brief defines the DOUBLE_FAULT_VECTOR ESR vector */
#define ESR_DOUBLE_FAULT_VECTOR ((uint32_t)8)
/** @brief defines the INVALID_TSS_VECTOR ESR vector */
#define ESR_INVALID_TSS_VECTOR ((uint32_t)10)
/** @brief defines the SEGMENT_NOT_PRESENT_VECTOR ESR vector */
#define ESR_SEGMENT_NOT_PRESENT_VECTOR ((uint32_t)11)
/** @brief defines the STACK_VECTOR ESR vector */
#define ESR_STACK_VECTOR ((uint32_t)12)
/** @brief defines the GENERAL_PROTECTION_VECTOR ESR vector */
#define ESR_GENERAL_PROTECTION_VECTOR ((uint32_t)13)
/** @brief defines the PAGE_FAULT_VECTOR ESR vector */
#define ESR_PAGE_FAULT_VECTOR ((uint32_t)14)
/** @brief defines the X87_FLOATING_POINT_EXCEPTION_PENDING_VECTOR ESR vector */
#define ESR_X87_FLOATING_POINT_EXCEPTION_PENDING_VECTOR ((uint32_t)16)
/** @brief defines the ALIGNMENT_CHECK_VECTOR ESR vector */
#define ESR_ALIGNMENT_CHECK_VECTOR ((uint32_t)17)
/** @brief defines the MACHINE_CHECK_VECTOR ESR vector */
#define ESR_MACHINE_CHECK_VECTOR ((uint32_t)18)
/** @brief defines the SIMD_FLOATING_POINT_VECTOR ESR vector */
#define ESR_SIMD_FLOATING_POINT_VECTOR ((uint32_t)19)
/** @brief defines the HYPERVISOR_INJECTION_EXCEPTION_VECTOR ESR vector */
#define ESR_HYPERVISOR_INJECTION_EXCEPTION_VECTOR ((uint32_t)28)
/** @brief defines the VMM_COMMUNICATION_EXCEPTION_VECTOR ESR vector */
#define ESR_VMM_COMMUNICATION_EXCEPTION_VECTOR ((uint32_t)29)
/** @brief defines the SECURITY_EXCEPTION_VECTOR ESR vector */
#define ESR_SECURITY_EXCEPTION_VECTOR ((uint32_t)30)

/** @brief defines the ESR selector used by the microkernel */
#define ESR_SELECTOR ((uint16_t)0x10)
/** @brief defines the ESR attributes used by the microkernel */
#define ESR_ATTRIB ((uint16_t)0x8E01)

/** @brief defines the PAT MSR used by the microkernel */
#define MK_MSR_IA32_PAT ((uint64_t)0x0606060606060606)

/** @brief defines the STAR MSR used by the microkernel */
#define MK_MSR_IA32_STAR ((uint64_t)0x001B001000000000)

/** @brief defines the FMASK MSR used by the microkernel */
#define MK_MSR_IA32_FMASK ((uint64_t)0xFFFFFFFFFFFFFFFD)

/**
 * <!-- description -->
 *   @brief The function's main purpose is to set up the state for the
 *     microkernel.
 *
 * <!-- inputs/outputs -->
 *   @param pml4t the mkcrokernel's root page table
 *   @param mk_elf_file the microkernel's ELF file
 *   @param mk_stack the microkernel's stack
 *   @param mk_stack_virt the microkernel's virtual address of the stack
 *   @param state where to save the newly set up state to
 *   @return 0 on success, LOADER_FAILURE on failure.
 */
int64_t
alloc_and_copy_mk_state(
    struct pml4t_t const *const pml4t,
    struct span_t const *const mk_elf_file,
    struct span_t const *const mk_stack,
    uint64_t const mk_stack_virt,
    struct state_save_t **const state)
{
    int64_t ret;

    struct bfelf_elf64_ehdr_t const *ehdr = ((void *)0);
    if (get_elf64_ehdr(mk_elf_file->addr, &ehdr)) {
        BFERROR("get_elf64_ehdr failed\n");
        return LOADER_FAILURE;
    }

    /**************************************************************************/
    /* Allocate the resulting state                                           */
    /**************************************************************************/

    *state = (struct state_save_t *)platform_alloc(HYPERVISOR_PAGE_SIZE);
    if (((void *)0) == *state) {
        BFERROR("platform_alloc failed\n");
        goto platform_alloc_state_failed;
    }

    /**************************************************************************/
    /* HVE Page                                                               */
    /**************************************************************************/

    (*state)->hve_page = platform_alloc(HYPERVISOR_PAGE_SIZE);
    if (((void *)0) == (*state)->hve_page) {
        BFERROR("platform_alloc failed\n");
        goto platform_alloc_hve_page_failed;
    }

    /**************************************************************************/
    /* Enable HVE                                                             */
    /**************************************************************************/

    if (enable_hve(*state)) {
        BFERROR("failed to enable HVE\n");
        goto enable_hve_failed;
    }

    /**************************************************************************/
    /* General Purpose Registers                                              */
    /**************************************************************************/

    (*state)->rip = ((uint64_t)ehdr->e_entry);
    (*state)->rsp = ((uint64_t)(mk_stack_virt + mk_stack->size));

    /**************************************************************************/
    /* Flags                                                                  */
    /**************************************************************************/

    (*state)->rflags = RFLAGS;

    /**************************************************************************/
    /* Task-State Segment                                                     */
    /**************************************************************************/

    (*state)->tss = (struct tss_t *)platform_alloc(HYPERVISOR_PAGE_SIZE);
    if (((void *)0) == (*state)->tss) {
        BFERROR("platform_alloc failed\n");
        goto platform_alloc_tss_failed;
    }

    (*state)->ist = platform_alloc(HYPERVISOR_PAGE_SIZE);
    if (((void *)0) == (*state)->ist) {
        BFERROR("platform_alloc failed\n");
        goto platform_alloc_ist_failed;
    }

    (*state)->tss->ist1 = ((uint64_t)(*state)->ist) + HYPERVISOR_PAGE_SIZE;
    (*state)->tss->iomap = ((uint16_t)sizeof(struct tss_t));

    /**************************************************************************/
    /* Descriptor Table Information                                           */
    /**************************************************************************/

    (*state)->gdtr.base = (uint64_t *)platform_alloc(HYPERVISOR_PAGE_SIZE);
    if (((void *)0) == (*state)->gdtr.base) {
        BFERROR("platform_alloc failed\n");
        goto platform_alloc_gdt_failed;
    }

    (*state)->idtr.base = (uint64_t *)platform_alloc(HYPERVISOR_PAGE_SIZE);
    if (((void *)0) == (*state)->idtr.base) {
        BFERROR("platform_alloc failed\n");
        goto platform_alloc_idt_failed;
    }

    (*state)->gdtr.limit = (uint16_t)(HYPERVISOR_PAGE_SIZE - ((uint64_t)1));
    (*state)->idtr.limit = (uint16_t)(HYPERVISOR_PAGE_SIZE - ((uint64_t)1));

    (*state)->cs_selector = MK_CS_SELECTOR;
    (*state)->cs_attrib = MK_CS_ATTRIB;
    (*state)->cs_limit = MK_CS_LIMIT;
    (*state)->cs_base = MK_CS_BASE;

    (*state)->ss_selector = MK_SS_SELECTOR;
    (*state)->ss_attrib = MK_SS_ATTRIB;
    (*state)->ss_limit = MK_SS_LIMIT;
    (*state)->ss_base = MK_SS_BASE;

    (*state)->tr_selector = MK_TR_SELECTOR;
    (*state)->tr_attrib = MK_TR_ATTRIB;
    (*state)->tr_limit = MK_TR_LIMIT;
    (*state)->tr_base = (uint64_t)(*state)->tss;

    ret = set_gdt_descriptor(
        &(*state)->gdtr,
        (*state)->cs_selector,
        (*state)->cs_base,
        (*state)->cs_limit,
        (*state)->cs_attrib);

    if (ret) {
        BFERROR("set_gdt_descriptor failed\n");
        goto set_descriptor_failed;
    }

    ret = set_gdt_descriptor(
        &(*state)->gdtr,
        (*state)->ss_selector,
        (*state)->ss_base,
        (*state)->ss_limit,
        (*state)->ss_attrib);

    if (ret) {
        BFERROR("set_gdt_descriptor failed\n");
        goto set_descriptor_failed;
    }

    ret = set_gdt_descriptor(
        &(*state)->gdtr,
        (*state)->tr_selector,
        (*state)->tr_base,
        (*state)->tr_limit,
        (*state)->tr_attrib);

    if (ret) {
        BFERROR("set_gdt_descriptor failed\n");
        goto set_descriptor_failed;
    }

    ret = set_gdt_descriptor(
        &(*state)->gdtr,
        EXT_CS_SELECTOR,
        EXT_CS_BASE,
        EXT_CS_LIMIT,
        EXT_CS_ATTRIB);

    if (ret) {
        BFERROR("set_gdt_descriptor failed\n");
        goto set_descriptor_failed;
    }

    ret = set_gdt_descriptor(
        &(*state)->gdtr,
        EXT_SS_SELECTOR,
        EXT_SS_BASE,
        EXT_SS_LIMIT,
        EXT_SS_ATTRIB);

    if (ret) {
        BFERROR("set_gdt_descriptor failed\n");
        goto set_descriptor_failed;
    }

    ret = set_idt_descriptor(
        &(*state)->idtr,
        ESR_DIVIDE_BY_ZERO_ERROR_VECTOR,
        (uint64_t)esr_default,
        ESR_SELECTOR,
        ESR_ATTRIB);

    if (ret) {
        BFERROR("set_idt_descriptor failed\n");
        goto set_descriptor_failed;
    }

    ret = set_idt_descriptor(
        &(*state)->idtr,
        ESR_DEBUG_VECTOR,
        (uint64_t)esr_default,
        ESR_SELECTOR,
        ESR_ATTRIB);

    if (ret) {
        BFERROR("set_idt_descriptor failed\n");
        goto set_descriptor_failed;
    }

    ret = set_idt_descriptor(
        &(*state)->idtr,
        ESR_NON_MASKABLE_INTERRUPT_VECTOR,
        (uint64_t)esr_nmi,
        ESR_SELECTOR,
        ESR_ATTRIB);

    if (ret) {
        BFERROR("set_idt_descriptor failed\n");
        goto set_descriptor_failed;
    }

    ret = set_idt_descriptor(
        &(*state)->idtr,
        ESR_BREAKPOINT_VECTOR,
        (uint64_t)esr_default,
        ESR_SELECTOR,
        ESR_ATTRIB);

    if (ret) {
        BFERROR("set_idt_descriptor failed\n");
        goto set_descriptor_failed;
    }

    ret = set_idt_descriptor(
        &(*state)->idtr,
        ESR_OVERFLOW_VECTOR,
        (uint64_t)esr_default,
        ESR_SELECTOR,
        ESR_ATTRIB);

    if (ret) {
        BFERROR("set_idt_descriptor failed\n");
        goto set_descriptor_failed;
    }

    ret = set_idt_descriptor(
        &(*state)->idtr,
        ESR_BOUND_RANGE_VECTOR,
        (uint64_t)esr_default,
        ESR_SELECTOR,
        ESR_ATTRIB);

    if (ret) {
        BFERROR("set_idt_descriptor failed\n");
        goto set_descriptor_failed;
    }

    ret = set_idt_descriptor(
        &(*state)->idtr,
        ESR_INVALID_OPCODE_VECTOR,
        (uint64_t)esr_default,
        ESR_SELECTOR,
        ESR_ATTRIB);

    if (ret) {
        BFERROR("set_idt_descriptor failed\n");
        goto set_descriptor_failed;
    }

    ret = set_idt_descriptor(
        &(*state)->idtr,
        ESR_DEVICE_NOT_AVAILABLE_VECTOR,
        (uint64_t)esr_default,
        ESR_SELECTOR,
        ESR_ATTRIB);

    if (ret) {
        BFERROR("set_idt_descriptor failed\n");
        goto set_descriptor_failed;
    }

    ret = set_idt_descriptor(
        &(*state)->idtr,
        ESR_DOUBLE_FAULT_VECTOR,
        (uint64_t)esr_df,
        ESR_SELECTOR,
        ESR_ATTRIB);

    if (ret) {
        BFERROR("set_idt_descriptor failed\n");
        goto set_descriptor_failed;
    }

    ret = set_idt_descriptor(
        &(*state)->idtr,
        ESR_INVALID_TSS_VECTOR,
        (uint64_t)esr_default,
        ESR_SELECTOR,
        ESR_ATTRIB);

    if (ret) {
        BFERROR("set_idt_descriptor failed\n");
        goto set_descriptor_failed;
    }

    ret = set_idt_descriptor(
        &(*state)->idtr,
        ESR_SEGMENT_NOT_PRESENT_VECTOR,
        (uint64_t)esr_default,
        ESR_SELECTOR,
        ESR_ATTRIB);

    if (ret) {
        BFERROR("set_idt_descriptor failed\n");
        goto set_descriptor_failed;
    }

    ret = set_idt_descriptor(
        &(*state)->idtr,
        ESR_STACK_VECTOR,
        (uint64_t)esr_default,
        ESR_SELECTOR,
        ESR_ATTRIB);

    if (ret) {
        BFERROR("set_idt_descriptor failed\n");
        goto set_descriptor_failed;
    }

    ret = set_idt_descriptor(
        &(*state)->idtr,
        ESR_GENERAL_PROTECTION_VECTOR,
        (uint64_t)esr_gpf,
        ESR_SELECTOR,
        ESR_ATTRIB);

    if (ret) {
        BFERROR("set_idt_descriptor failed\n");
        goto set_descriptor_failed;
    }

    ret = set_idt_descriptor(
        &(*state)->idtr,
        ESR_PAGE_FAULT_VECTOR,
        (uint64_t)esr_pf,
        ESR_SELECTOR,
        ESR_ATTRIB);

    if (ret) {
        BFERROR("set_idt_descriptor failed\n");
        goto set_descriptor_failed;
    }

    ret = set_idt_descriptor(
        &(*state)->idtr,
        ESR_X87_FLOATING_POINT_EXCEPTION_PENDING_VECTOR,
        (uint64_t)esr_default,
        ESR_SELECTOR,
        ESR_ATTRIB);

    if (ret) {
        BFERROR("set_idt_descriptor failed\n");
        goto set_descriptor_failed;
    }

    ret = set_idt_descriptor(
        &(*state)->idtr,
        ESR_ALIGNMENT_CHECK_VECTOR,
        (uint64_t)esr_default,
        ESR_SELECTOR,
        ESR_ATTRIB);

    if (ret) {
        BFERROR("set_idt_descriptor failed\n");
        goto set_descriptor_failed;
    }

    ret = set_idt_descriptor(
        &(*state)->idtr,
        ESR_MACHINE_CHECK_VECTOR,
        (uint64_t)esr_default,
        ESR_SELECTOR,
        ESR_ATTRIB);

    if (ret) {
        BFERROR("set_idt_descriptor failed\n");
        goto set_descriptor_failed;
    }

    ret = set_idt_descriptor(
        &(*state)->idtr,
        ESR_SIMD_FLOATING_POINT_VECTOR,
        (uint64_t)esr_default,
        ESR_SELECTOR,
        ESR_ATTRIB);

    if (ret) {
        BFERROR("set_idt_descriptor failed\n");
        goto set_descriptor_failed;
    }

    ret = set_idt_descriptor(
        &(*state)->idtr,
        ESR_HYPERVISOR_INJECTION_EXCEPTION_VECTOR,
        (uint64_t)esr_default,
        ESR_SELECTOR,
        ESR_ATTRIB);

    if (ret) {
        BFERROR("set_idt_descriptor failed\n");
        goto set_descriptor_failed;
    }

    ret = set_idt_descriptor(
        &(*state)->idtr,
        ESR_VMM_COMMUNICATION_EXCEPTION_VECTOR,
        (uint64_t)esr_default,
        ESR_SELECTOR,
        ESR_ATTRIB);

    if (ret) {
        BFERROR("set_idt_descriptor failed\n");
        goto set_descriptor_failed;
    }

    ret = set_idt_descriptor(
        &(*state)->idtr,
        ESR_SECURITY_EXCEPTION_VECTOR,
        (uint64_t)esr_default,
        ESR_SELECTOR,
        ESR_ATTRIB);

    if (ret) {
        BFERROR("set_idt_descriptor failed\n");
        goto set_descriptor_failed;
    }

    /**************************************************************************/
    /* Control Registers                                                      */
    /**************************************************************************/

    (*state)->cr0 = intrinsic_scr0();
    (*state)->cr3 = platform_virt_to_phys(pml4t);
    (*state)->cr4 = intrinsic_scr4();

    if (((uint64_t)0) == (*state)->cr3) {
        BFERROR("platform_virt_to_phys failed\n");
        goto platform_virt_to_phys_cr3_failed;
    }

    /**
     * TODO:
     * - Check the values of CR0, CR4
     */

    /**************************************************************************/
    /* MSRs                                                                   */
    /**************************************************************************/

    (*state)->ia32_efer = intrinsic_rdmsr(MSR_IA32_EFER);
    (*state)->ia32_star = MK_MSR_IA32_STAR;
    (*state)->ia32_fmask = MK_MSR_IA32_FMASK;
    (*state)->ia32_pat = MK_MSR_IA32_PAT;

    /**
     * TODO:
     * - Check the values of EFER
     */

    return LOADER_SUCCESS;

platform_virt_to_phys_cr3_failed:
set_descriptor_failed:

    platform_free((*state)->idtr.base, HYPERVISOR_PAGE_SIZE);
platform_alloc_idt_failed:

    platform_free((*state)->gdtr.base, HYPERVISOR_PAGE_SIZE);
platform_alloc_gdt_failed:

    platform_free((*state)->ist, HYPERVISOR_PAGE_SIZE);
platform_alloc_ist_failed:

    platform_free((*state)->tss, HYPERVISOR_PAGE_SIZE);
platform_alloc_tss_failed:

    disable_hve();
enable_hve_failed:

    platform_free((*state)->hve_page, HYPERVISOR_PAGE_SIZE);
platform_alloc_hve_page_failed:

    platform_free(*state, HYPERVISOR_PAGE_SIZE);
platform_alloc_state_failed:

    *state = ((void *)0);
    return LOADER_FAILURE;
}
