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

#include <debug.h>
#include <state_save_t.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief Outputs the contents of a provided mk state.
 *
 * <!-- inputs/outputs -->
 *   @param state the mk state to output
 *   @param cpu the CPU that this mk state belongs to
 *   @return 0 on success, LOADER_FAILURE on failure.
 */
void
dump_mk_state(struct state_save_t *const state, uint32_t const cpu)
{
    BFINFO("mk state on cpu #%u:\n", cpu);
    BFINFO(" - virt: 0x%016" PRIx64 "\n", (uint64_t)state);

    BFINFO(" - rax: 0x%016" PRIx64 "\n", state->rax);
    BFINFO(" - rbx: 0x%016" PRIx64 "\n", state->rbx);
    BFINFO(" - rcx: 0x%016" PRIx64 "\n", state->rcx);
    BFINFO(" - rdx: 0x%016" PRIx64 "\n", state->rdx);
    BFINFO(" - rbp: 0x%016" PRIx64 "\n", state->rbp);
    BFINFO(" - rsi: 0x%016" PRIx64 "\n", state->rsi);
    BFINFO(" - rdi: 0x%016" PRIx64 "\n", state->rdi);
    BFINFO(" - r8: 0x%016" PRIx64 "\n", state->r8);
    BFINFO(" - r9: 0x%016" PRIx64 "\n", state->r9);
    BFINFO(" - r10: 0x%016" PRIx64 "\n", state->r10);
    BFINFO(" - r11: 0x%016" PRIx64 "\n", state->r11);
    BFINFO(" - r12: 0x%016" PRIx64 "\n", state->r12);
    BFINFO(" - r13: 0x%016" PRIx64 "\n", state->r13);
    BFINFO(" - r14: 0x%016" PRIx64 "\n", state->r14);
    BFINFO(" - r15: 0x%016" PRIx64 "\n", state->r15);
    BFINFO(" - rip: 0x%016" PRIx64 "\n", state->rip);
    BFINFO(" - rsp: 0x%016" PRIx64 "\n", state->rsp);

    BFINFO(" - rflags: 0x%016" PRIx64 "\n", state->rflags);

    BFINFO(" - tss: 0x%016" PRIx64 "\n", (uint64_t)state->tss);
    BFINFO(" - ist: 0x%016" PRIx64 "\n", (uint64_t)state->ist);
    BFINFO(" - tss->rsp0: 0x%016" PRIx64 "\n", state->tss->rsp0);
    BFINFO(" - tss->rsp1: 0x%016" PRIx64 "\n", state->tss->rsp1);
    BFINFO(" - tss->rsp2: 0x%016" PRIx64 "\n", state->tss->rsp2);
    BFINFO(" - tss->ist1: 0x%016" PRIx64 "\n", state->tss->ist1);
    BFINFO(" - tss->ist2: 0x%016" PRIx64 "\n", state->tss->ist2);
    BFINFO(" - tss->ist3: 0x%016" PRIx64 "\n", state->tss->ist3);
    BFINFO(" - tss->ist4: 0x%016" PRIx64 "\n", state->tss->ist4);
    BFINFO(" - tss->ist5: 0x%016" PRIx64 "\n", state->tss->ist5);
    BFINFO(" - tss->ist6: 0x%016" PRIx64 "\n", state->tss->ist6);
    BFINFO(" - tss->ist7: 0x%016" PRIx64 "\n", state->tss->ist7);
    BFINFO(" - tss->iomap: 0x%x\n", (uint32_t)state->tss->iomap);

    BFINFO(" - gdtr.base: 0x%016" PRIx64 "\n", (uint64_t)state->gdtr.base);
    BFINFO(" - gdtr.limit: 0x%04x\n", state->gdtr.limit);
    BFINFO(" - idtr.base: 0x%016" PRIx64 "\n", (uint64_t)state->idtr.base);
    BFINFO(" - idtr.limit: 0x%04x\n", state->idtr.limit);
    BFINFO(" - es_selector: 0x%04x\n", state->es_selector);
    BFINFO(" - es_attrib: 0x%04x\n", state->es_attrib);
    BFINFO(" - es_limit: 0x%08x\n", state->es_limit);
    BFINFO(" - es_base: 0x%016" PRIx64 "\n", state->es_base);
    BFINFO(" - cs_selector: 0x%04x\n", state->cs_selector);
    BFINFO(" - cs_attrib: 0x%04x\n", state->cs_attrib);
    BFINFO(" - cs_limit: 0x%08x\n", state->cs_limit);
    BFINFO(" - cs_base: 0x%016" PRIx64 "\n", state->cs_base);
    BFINFO(" - ss_selector: 0x%04x\n", state->ss_selector);
    BFINFO(" - ss_attrib: 0x%04x\n", state->ss_attrib);
    BFINFO(" - ss_limit: 0x%08x\n", state->ss_limit);
    BFINFO(" - ss_base: 0x%016" PRIx64 "\n", state->ss_base);
    BFINFO(" - ds_selector: 0x%04x\n", state->ds_selector);
    BFINFO(" - ds_attrib: 0x%04x\n", state->ds_attrib);
    BFINFO(" - ds_limit: 0x%08x\n", state->ds_limit);
    BFINFO(" - ds_base: 0x%016" PRIx64 "\n", state->ds_base);
    BFINFO(" - fs_selector: 0x%04x\n", state->fs_selector);
    BFINFO(" - fs_attrib: 0x%04x\n", state->fs_attrib);
    BFINFO(" - fs_limit: 0x%08x\n", state->fs_limit);
    BFINFO(" - fs_base: 0x%016" PRIx64 "\n", state->fs_base);
    BFINFO(" - gs_selector: 0x%04x\n", state->gs_selector);
    BFINFO(" - gs_attrib: 0x%04x\n", state->gs_attrib);
    BFINFO(" - gs_limit: 0x%08x\n", state->gs_limit);
    BFINFO(" - gs_base: 0x%016" PRIx64 "\n", state->gs_base);
    BFINFO(" - ldtr_selector: 0x%04x\n", state->ldtr_selector);
    BFINFO(" - ldtr_attrib: 0x%04x\n", state->ldtr_attrib);
    BFINFO(" - ldtr_limit: 0x%08x\n", state->ldtr_limit);
    BFINFO(" - ldtr_base: 0x%016" PRIx64 "\n", state->ldtr_base);
    BFINFO(" - tr_selector: 0x%04x\n", state->tr_selector);
    BFINFO(" - tr_attrib: 0x%04x\n", state->tr_attrib);
    BFINFO(" - tr_limit: 0x%08x\n", state->tr_limit);
    BFINFO(" - tr_base: 0x%016" PRIx64 "\n", state->tr_base);

    BFINFO(" - cr0: 0x%016" PRIx64 "\n", state->cr0);
    BFINFO(" - cr2: 0x%016" PRIx64 "\n", state->cr2);
    BFINFO(" - cr3: 0x%016" PRIx64 "\n", state->cr3);
    BFINFO(" - cr4: 0x%016" PRIx64 "\n", state->cr4);

    BFINFO(" - dr6: 0x%016" PRIx64 "\n", state->dr6);
    BFINFO(" - dr7: 0x%016" PRIx64 "\n", state->dr7);

    BFINFO(" - efer: 0x%016" PRIx64 "\n", state->ia32_efer);
    BFINFO(" - star: 0x%016" PRIx64 "\n", state->ia32_star);
    BFINFO(" - lstar: 0x%016" PRIx64 "\n", state->ia32_lstar);
    BFINFO(" - cstar: 0x%016" PRIx64 "\n", state->ia32_cstar);
    BFINFO(" - fmask: 0x%016" PRIx64 "\n", state->ia32_fmask);
    BFINFO(" - fs_base: 0x%016" PRIx64 "\n", state->ia32_fs_base);
    BFINFO(" - gs_base: 0x%016" PRIx64 "\n", state->ia32_gs_base);
    BFINFO(" - kernel_gs_base: 0x%016" PRIx64 "\n", state->ia32_kernel_gs_base);
    BFINFO(" - sysenter_cs: 0x%016" PRIx64 "\n", state->ia32_sysenter_cs);
    BFINFO(" - sysenter_esp: 0x%016" PRIx64 "\n", state->ia32_sysenter_esp);
    BFINFO(" - sysenter_eip: 0x%016" PRIx64 "\n", state->ia32_sysenter_eip);
    BFINFO(" - pat: 0x%016" PRIx64 "\n", state->ia32_pat);
    BFINFO(" - debugctl: 0x%016" PRIx64 "\n", state->ia32_debugctl);

    BFINFO(" - hve_page: 0x%016" PRIx64 "\n", (uint64_t)state->hve_page);

    BFINFO(
        " - promote_handler: 0x%016" PRIx64 "\n",
        (uint64_t)state->promote_handler);
    BFINFO(
        " - esr_default_handler: 0x%016" PRIx64 "\n",
        (uint64_t)state->esr_default_handler);
    BFINFO(
        " - esr_df_handler: 0x%016" PRIx64 "\n",
        (uint64_t)state->esr_df_handler);
    BFINFO(
        " - esr_gpf_handler: 0x%016" PRIx64 "\n",
        (uint64_t)state->esr_gpf_handler);
    BFINFO(
        " - esr_nmi_handler: 0x%016" PRIx64 "\n",
        (uint64_t)state->esr_nmi_handler);
    BFINFO(
        " - esr_pf_handler: 0x%016" PRIx64 "\n",
        (uint64_t)state->esr_pf_handler);

    BFINFO(" - nmi: 0x%016" PRIx64 "\n", state->nmi);
}
