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

#include <loader_arch.h>
#include <loader_arch_context.h>
#include <loader_check_canonical.h>
#include <loader_check_page_aligned.h>
#include <loader_check_valid_physical.h>
#include <loader_debug.h>
#include <loader_gdt.h>
#include <loader_idt.h>
#include <loader_intrinsics.h>
#include <loader_platform.h>
#include <loader_types.h>
#include <loader.h>

/**
 * <!-- description -->
 *   @brief Enable Secure Virtual Machine support. This turns on the
 *     ability to use the VMRUN, VMLOAD and VMSAVE instructions, as well
 *     as some other support instructions like stgi and clgi.
 *
 * <!-- inputs/outputs -->
 *   @return Returns 0 on success
 */
int64_t
enable_svm(void)
{
    uint64_t efer = arch_rdmsr(MSR_EFER);

    if ((efer & MSR_EFER_SVME) != 0) {
        BFERROR("SVM is already running. Is another hypervisor running?\n");
        return LOADER_FAILURE;
    }

    arch_wrmsr(MSR_EFER, efer | MSR_EFER_SVME);
    return 0;
}

/**
 * <!-- description -->
 *   @brief Allocate, validate and clear a block of memory.
 *
 * <!-- inputs/outputs -->
 *   @param virt the location to store the newly allocated memory
 *   @param size the size of the memory to allocate
 *   @param ac the architecture specific context for this cpu
 *   @return Returns 0 on success
 */
int64_t
setup_virt(void **virt, uintptr_t const size, struct loader_arch_context_t *ac)
{
    if (NULL == virt) {
        BFERROR("invalid argument\n");
        return LOADER_FAILURE;
    }

    if (NULL != *virt) {
        BFERROR("virtual address was never freed\n");
        return LOADER_FAILURE;
    }

    *virt = platform_alloc(size);
    if (NULL == *virt) {
        BFERROR("failed to allocate memory\n");
        return LOADER_FAILURE;
    }

    if (check_page_aligned((uintptr_t)*virt, ac)) {
        BFERROR("check_page_aligned failed\n");
        return LOADER_FAILURE;
    }

    if (check_canonical((uintptr_t)*virt, ac)) {
        BFERROR("check_canonical failed\n");
        return LOADER_FAILURE;
    }

    if (platform_memset(*virt, 0, size)) {
        BFERROR("platform_memset failed\n");
        return LOADER_FAILURE;
    }

    return 0;
}

/**
 * <!-- description -->
 *   @brief Get and validate the physical address of an existing virtual
 *     address
 *
 * <!-- inputs/outputs -->
 *   @param phys the location to store the physical address
 *   @param virt the virtual address to get the physical address of
 *   @param ac the architecture specific context for this cpu
 *   @return Returns 0 on success
 */
int64_t
setup_phys(uintptr_t *phys, void *virt, struct loader_arch_context_t *ac)
{
    if (NULL == phys) {
        BFERROR("invalid argument\n");
        return LOADER_FAILURE;
    }

    if (NULL == virt) {
        BFERROR("invalid argument\n");
        return LOADER_FAILURE;
    }

    if (0U != *phys) {
        BFERROR("physical address was never reset\n");
        return LOADER_FAILURE;
    }

    *phys = platform_virt_to_phys(virt);
    if (0U == *phys) {
        BFERROR("platform_virt_to_phys failed\n");
        return LOADER_FAILURE;
    }

    if (check_page_aligned(*phys, ac)) {
        BFERROR("check_page_aligned failed\n");
        return LOADER_FAILURE;
    }

    if (check_valid_physical(*phys, ac)) {
        BFERROR("check_valid_physical failed\n");
        return LOADER_FAILURE;
    }

    return 0;
}

/**
 * <!-- description -->
 *   @brief Prepare the host VMCB. The host VMCB is used to store state
 *     that the VMRUN function does not save for us. This does not
 *     include the state save or the xsave state. Note that we must also
 *     store the host stack so that the VMLAUNCH code can use it as needed.
 *
 * <!-- inputs/outputs -->
 *   @param ac the architecture specific context for this cpu
 *   @return Returns 0 on success
 */
int64_t
prepare_host_vmcb(struct loader_arch_context_t *ac)
{
    if (NULL == ac) {
        BFERROR("invalid argument\n");
        return LOADER_FAILURE;
    }

    if (0U == ac->host_stack_size) {
        BFERROR("invalid host stack size\n");
        return LOADER_FAILURE;
    }

    /**
     * Notes:
     * - Allocate, validate and clear the host's VMCB
     * - Get and validate the host VMCB's physical address
     * - Allocate, validate and clear the host's stack
     */

    if (setup_virt((void **)&ac->host_vmcb, sizeof(struct vmcb_t), ac)) {
        BFERROR("setup_virt failed\n");
        return LOADER_FAILURE;
    }

    if (setup_phys(&ac->host_vmcb_phys, ac->host_vmcb, ac)) {
        BFERROR("setup_phys failed\n");
        return LOADER_FAILURE;
    }

    if (setup_virt(&ac->host_stack, ac->host_stack_size, ac)) {
        BFERROR("setup_virt failed\n");
        return LOADER_FAILURE;
    }

    /**
     * Notes:
     * - Store the host RSP. Note that RSP must be at the top of the stack
     *   so that it can be used once VMRUN is used.
     */

    ac->host_vmcb->rsp = (uintptr_t)ac->host_stack + ac->host_stack_size;

    /**
     * Notes:
     * - Get and store the FS, GS, TR and LDTR
     * - Get and store the KernelGsBase
     * - Get and store the STAR, LSTAR, CSTAR, SFMASK
     * - Get and store the SYSENTER_CS, SYSENTER_ESP, SYSENTER_EIP
     */

    arch_vmsave(ac->host_vmcb_phys);

    /**
     * Notes:
     * - Done.
     */

    return 0;
}

/**
 * <!-- description -->
 *   @brief Prepare the guest VMCB. The guest VMCB is used to store state
 *     that the VMRUN function saves for us. This does not include the
 *     state save or the xsave state. Note that since the VMRUN will use
 *     the guest VMCB to save and load the guest state for us, we must
 *     populate it with the initial state of the guest.
 *
 * <!-- inputs/outputs -->
 *   @param ac the architecture specific context for this cpu
 *   @return Returns 0 on success
 */
int64_t
prepare_guest_vmcb(struct loader_arch_context_t *ac)
{
    uint16_t es_index = 0;
    uint16_t cs_index = 0;
    uint16_t ss_index = 0;
    uint16_t ds_index = 0;

    struct global_descriptor_table_register gdtr = {0};
    struct interrupt_descriptor_table_register idtr = {0};

    if (NULL == ac) {
        BFERROR("invalid argument\n");
        return LOADER_FAILURE;
    }

    /**
     * Notes:
     * - Allocate, validate and clear the guest's VMCB
     * - Get and validate the guest VMCB's physical address
     */

    if (setup_virt((void **)&ac->guest_vmcb, sizeof(struct vmcb_t), ac)) {
        BFERROR("setup_virt failed\n");
        return LOADER_FAILURE;
    }

    if (setup_phys(&ac->guest_vmcb_phys, ac->guest_vmcb, ac)) {
        BFERROR("setup_phys failed\n");
        return LOADER_FAILURE;
    }

    /**
     * Notes:
     * - Turn on the minimum number of controls. AMD requires that the VMRUN
     *   control is turned on, meaning all attempts to call the VMRUN
     *   instruction will fail.
     */
    ac->guest_vmcb->intercept_instruction1 |= VMCB_INTERCEPT_INSTRUCTION1_CPUID;
    ac->guest_vmcb->intercept_instruction1 |= VMCB_INTERCEPT_INSTRUCTION1_VMRUN;
    ac->guest_vmcb->intercept_instruction1 |= VMCB_INTERCEPT_INSTRUCTION1_VMMCALL;

    /**
     * Notes:
     * - Set the ASID which is a TLB tag for removing the need for flushing
     *   the TLB on world switches. The root OS always has an ASID of 1 while
     *   the host always has an ASID of 0. All guest VMs have an ASID of
     *   something greater than 1.
     */

    ac->guest_vmcb->guest_asid = 1;

    /**
     * Note:
     * - Get the GDTR and the IDTR. These will be used to set up some
     *   additional fields in the VMCB.
     */

    arch_sgdt(&gdtr);
    arch_sidt(&idtr);

    ac->guest_vmcb->gdtr_limit = gdtr.limit;
    ac->guest_vmcb->gdtr_base = (uintptr_t)gdtr.base;
    ac->guest_vmcb->idtr_limit = idtr.limit;
    ac->guest_vmcb->idtr_base = (uintptr_t)idtr.base;

    BFDEBUG("gdtr_limit: 0x%x\n", ac->guest_vmcb->gdtr_limit);
    BFDEBUG("gdtr_base: 0x%" PRIx64 "\n", ac->guest_vmcb->gdtr_base);
    BFDEBUG("idtr_limit: 0x%x\n", ac->guest_vmcb->idtr_limit);
    BFDEBUG("idtr_base: 0x%" PRIx64 "\n", ac->guest_vmcb->idtr_base);

    /**
     * Note:
     * - Get segment selectors. Note that we only get ES, CS, SS and DS as
     *   the vmload/vmsave instructions will get the others for us.
     */

    ac->guest_vmcb->es_selector = arch_reades();
    ac->guest_vmcb->cs_selector = arch_readcs();
    ac->guest_vmcb->ss_selector = arch_readss();
    ac->guest_vmcb->ds_selector = arch_readds();

    BFDEBUG("es_selector: 0x%x\n", ac->guest_vmcb->es_selector);
    BFDEBUG("cs_selector: 0x%x\n", ac->guest_vmcb->cs_selector);
    BFDEBUG("ss_selector: 0x%x\n", ac->guest_vmcb->ss_selector);
    BFDEBUG("ds_selector: 0x%x\n", ac->guest_vmcb->ds_selector);

    /**
     * Note:
     * - Get segment descriptor indexes. This is needed because the segment
     *   selector has additional bits for privilege levels, etc.., so we
     *   need to remove these to get access to the actual indexes into the
     *   global descriptor table.
     */

    es_index = ac->guest_vmcb->es_selector >> 3U;
    cs_index = ac->guest_vmcb->cs_selector >> 3U;
    ss_index = ac->guest_vmcb->ss_selector >> 3U;
    ds_index = ac->guest_vmcb->ds_selector >> 3U;

    BFDEBUG("es_index: 0x%x\n", es_index);
    BFDEBUG("cs_index: 0x%x\n", cs_index);
    BFDEBUG("ss_index: 0x%x\n", ss_index);
    BFDEBUG("ds_index: 0x%x\n", ds_index);

    /**
     * Note:
     * - The next step is to set the visible and hidden fields for each of
     *   the descriptors.
     * - The limit hidden field is always in bytes (although this is not
     *   documented). For this reason, the helper functions will look at
     *   the granularity bit and convert the limit to bytes as needed.
     * - The access rights hidden field is always shifted right to form a
     *   12 bit. Again, this is not documented as the LAR instruction
     *   does not work this way.
     */

    ac->guest_vmcb->es_attrib = get_segment_descriptor_attrib(&gdtr, es_index);
    ac->guest_vmcb->es_limit = get_segment_descriptor_limit(&gdtr, es_index);
    ac->guest_vmcb->es_base = get_segment_descriptor_base(&gdtr, es_index);
    ac->guest_vmcb->cs_attrib = get_segment_descriptor_attrib(&gdtr, cs_index);
    ac->guest_vmcb->cs_limit = get_segment_descriptor_limit(&gdtr, cs_index);
    ac->guest_vmcb->cs_base = get_segment_descriptor_base(&gdtr, cs_index);
    ac->guest_vmcb->ss_attrib = get_segment_descriptor_attrib(&gdtr, ss_index);
    ac->guest_vmcb->ss_limit = get_segment_descriptor_limit(&gdtr, ss_index);
    ac->guest_vmcb->ss_base = get_segment_descriptor_base(&gdtr, ss_index);
    ac->guest_vmcb->ds_attrib = get_segment_descriptor_attrib(&gdtr, ds_index);
    ac->guest_vmcb->ds_limit = get_segment_descriptor_limit(&gdtr, ds_index);
    ac->guest_vmcb->ds_base = get_segment_descriptor_base(&gdtr, ds_index);

    BFDEBUG("es_attrib: 0x%x\n", ac->guest_vmcb->es_attrib);
    BFDEBUG("es_limit: 0x%x\n", ac->guest_vmcb->es_limit);
    BFDEBUG("es_base: 0x%" PRIx64 "\n", ac->guest_vmcb->es_base);
    BFDEBUG("cs_attrib: 0x%x\n", ac->guest_vmcb->cs_attrib);
    BFDEBUG("cs_limit: 0x%x\n", ac->guest_vmcb->cs_limit);
    BFDEBUG("cs_base: 0x%" PRIx64 "\n", ac->guest_vmcb->cs_base);
    BFDEBUG("ss_attrib: 0x%x\n", ac->guest_vmcb->ss_attrib);
    BFDEBUG("ss_limit: 0x%x\n", ac->guest_vmcb->ss_limit);
    BFDEBUG("ss_base: 0x%" PRIx64 "\n", ac->guest_vmcb->ss_base);
    BFDEBUG("ds_attrib: 0x%x\n", ac->guest_vmcb->ds_attrib);
    BFDEBUG("ds_limit: 0x%x\n", ac->guest_vmcb->ds_limit);
    BFDEBUG("ds_base: 0x%" PRIx64 "\n", ac->guest_vmcb->ds_base);

    if (0xFFFFFFFFU == ac->guest_vmcb->es_attrib) {
        BFERROR("failed to get the es segment's attributes\n");
        return LOADER_FAILURE;
    }

    if (0xFFFFFFFFU == ac->guest_vmcb->cs_attrib) {
        BFERROR("failed to get the cs segment's attributes\n");
        return LOADER_FAILURE;
    }

    if (0xFFFFFFFFU == ac->guest_vmcb->ss_attrib) {
        BFERROR("failed to get the ss segment's attributes\n");
        return LOADER_FAILURE;
    }

    if (0xFFFFFFFFU == ac->guest_vmcb->ds_attrib) {
        BFERROR("failed to get the ds segment's attributes\n");
        return LOADER_FAILURE;
    }

    if (1U == ac->guest_vmcb->es_limit) {
        BFERROR("failed to get the es segment's limit\n");
        return LOADER_FAILURE;
    }

    if (1U == ac->guest_vmcb->cs_limit) {
        BFERROR("failed to get the cs segment's limit\n");
        return LOADER_FAILURE;
    }

    if (1U == ac->guest_vmcb->ss_limit) {
        BFERROR("failed to get the ss segment's limit\n");
        return LOADER_FAILURE;
    }

    if (1U == ac->guest_vmcb->ds_limit) {
        BFERROR("failed to get the ds segment's limit\n");
        return LOADER_FAILURE;
    }

    if (0xFFFFFFFFU == ac->guest_vmcb->es_base) {
        BFERROR("failed to get the es segment's base address\n");
        return LOADER_FAILURE;
    }

    if (0xFFFFFFFFU == ac->guest_vmcb->cs_base) {
        BFERROR("failed to get the cs segment's base address\n");
        return LOADER_FAILURE;
    }

    if (0xFFFFFFFFU == ac->guest_vmcb->ss_base) {
        BFERROR("failed to get the ss segment's base address\n");
        return LOADER_FAILURE;
    }

    if (0xFFFFFFFFU == ac->guest_vmcb->ds_base) {
        BFERROR("failed to get the ds segment's base address\n");
        return LOADER_FAILURE;
    }

    /**
     * Note:
     * - Get the VMCB's model specific registers.
     */

    ac->guest_vmcb->efer = arch_rdmsr(MSR_EFER);
    ac->guest_vmcb->g_pat = arch_rdmsr(MSR_PAT);
    ac->guest_vmcb->dbgctl = arch_rdmsr(MSR_DEBUGCTL);

    BFDEBUG("efer: 0x%" PRIx64 "\n", ac->guest_vmcb->efer);
    BFDEBUG("g_pat: 0x%" PRIx64 "\n", ac->guest_vmcb->g_pat);
    BFDEBUG("dbgctl: 0x%" PRIx64 "\n", ac->guest_vmcb->dbgctl);

    /**
     * Note:
     * - Get the VMCB's control registers.
     */

    ac->guest_vmcb->cr0 = arch_readcr0();
    ac->guest_vmcb->cr2 = arch_readcr2();
    ac->guest_vmcb->cr3 = arch_readcr3();
    ac->guest_vmcb->cr4 = arch_readcr4();

    BFDEBUG("cr0: 0x%" PRIx64 "\n", ac->guest_vmcb->cr0);
    BFDEBUG("cr2: 0x%" PRIx64 "\n", ac->guest_vmcb->cr2);
    BFDEBUG("cr3: 0x%" PRIx64 "\n", ac->guest_vmcb->cr3);
    BFDEBUG("cr4: 0x%" PRIx64 "\n", ac->guest_vmcb->cr4);

    /**
     * Note:
     * - Get the VMCB's debug registers.
     */

    ac->guest_vmcb->dr6 = arch_readdr6();
    ac->guest_vmcb->dr7 = arch_readdr7();

    BFDEBUG("dr6: 0x%" PRIx64 "\n", ac->guest_vmcb->dr6);
    BFDEBUG("dr7: 0x%" PRIx64 "\n", ac->guest_vmcb->dr7);

    /**
     * Note:
     * - Get and store the FS, GS, TR and LDTR
     * - Get and store the KernelGsBase
     * - Get and store the STAR, LSTAR, CSTAR, SFMASK
     * - Get and store the SYSENTER_CS, SYSENTER_ESP, SYSENTER_EIP
     */

    arch_vmsave(ac->guest_vmcb_phys);

    BFDEBUG("fs_selector: 0x%x\n", ac->guest_vmcb->fs_selector);
    BFDEBUG("fs_attrib: 0x%x\n", ac->guest_vmcb->fs_attrib);
    BFDEBUG("fs_limit: 0x%x\n", ac->guest_vmcb->fs_limit);
    BFDEBUG("fs_base: 0x%" PRIx64 "\n", ac->guest_vmcb->fs_base);
    BFDEBUG("gs_selector: 0x%x\n", ac->guest_vmcb->gs_selector);
    BFDEBUG("gs_attrib: 0x%x\n", ac->guest_vmcb->gs_attrib);
    BFDEBUG("gs_limit: 0x%x\n", ac->guest_vmcb->gs_limit);
    BFDEBUG("gs_base: 0x%" PRIx64 "\n", ac->guest_vmcb->gs_base);
    BFDEBUG("tr_selector: 0x%x\n", ac->guest_vmcb->tr_selector);
    BFDEBUG("tr_attrib: 0x%x\n", ac->guest_vmcb->tr_attrib);
    BFDEBUG("tr_limit: 0x%x\n", ac->guest_vmcb->tr_limit);
    BFDEBUG("tr_base: 0x%" PRIx64 "\n", ac->guest_vmcb->tr_base);
    BFDEBUG("ldtr_selector: 0x%x\n", ac->guest_vmcb->ldtr_selector);
    BFDEBUG("ldtr_attrib: 0x%x\n", ac->guest_vmcb->ldtr_attrib);
    BFDEBUG("ldtr_limit: 0x%x\n", ac->guest_vmcb->ldtr_limit);
    BFDEBUG("ldtr_base: 0x%" PRIx64 "\n", ac->guest_vmcb->ldtr_base);
    BFDEBUG("kernel_gs_base: 0x%" PRIx64 "\n", ac->guest_vmcb->kernel_gs_base);
    BFDEBUG("star: 0x%" PRIx64 "\n", ac->guest_vmcb->star);
    BFDEBUG("lstar: 0x%" PRIx64 "\n", ac->guest_vmcb->lstar);
    BFDEBUG("cstar: 0x%" PRIx64 "\n", ac->guest_vmcb->cstar);
    BFDEBUG("sfmask: 0x%" PRIx64 "\n", ac->guest_vmcb->sfmask);
    BFDEBUG("sysenter_cs: 0x%" PRIx64 "\n", ac->guest_vmcb->sysenter_cs);
    BFDEBUG("sysenter_esp: 0x%" PRIx64 "\n", ac->guest_vmcb->sysenter_esp);
    BFDEBUG("sysenter_eip: 0x%" PRIx64 "\n", ac->guest_vmcb->sysenter_eip);

    /**
     * Notes:
     * - Done.
     */

    return 0;
}

/**
 * <!-- description -->
 *   @brief Prepare the host state save. The host state save is used by the
 *     VMRUN instruction to save/load some of the host's state. This does
 *     not include the host VMCB state or the xsave state.
 *
 * <!-- inputs/outputs -->
 *   @param ac the architecture specific context for this cpu
 *   @return Returns 0 on success
 */
int64_t
prepare_host_state_save(struct loader_arch_context_t *ac)
{
    if (NULL == ac) {
        BFERROR("invalid argument\n");
        return LOADER_FAILURE;
    }

    /**
     * Notes:
     * - Allocate, validate and clear the host's state save
     * - Get and validate the host state save's physical address
     */

    if (setup_virt((void **)&ac->host_save, sizeof(struct state_save_t), ac)) {
        BFERROR("setup_virt failed\n");
        return LOADER_FAILURE;
    }

    if (setup_phys(&ac->host_save_phys, ac->host_save, ac)) {
        BFERROR("setup_phys failed\n");
        return LOADER_FAILURE;
    }

    /**
     * Note:
     * - Set the host state save area for this CPU.
     */

    arch_wrmsr(MSR_VM_HSAVE_PA, ac->host_save_phys);

    /**
     * Notes:
     * - Done.
     */

    return 0;
}

/**
 * <!-- description -->
 *   @brief Prepare the guest state save. The guest state save is used to
 *     store the state that the VMRUN does not store for the guest. This does
 *     not include the guest VMCB state or the xsave state.
 *
 * <!-- inputs/outputs -->
 *   @param ac the architecture specific context for this cpu
 *   @return Returns 0 on success
 */
int64_t
prepare_guest_state_save(struct loader_arch_context_t *ac)
{
    if (NULL == ac) {
        BFERROR("invalid argument\n");
        return LOADER_FAILURE;
    }

    /**
     * Notes:
     * - Allocate, validate and clear the guest's state save
     * - Get and validate the guest state save's physical address
     */

    if (setup_virt((void **)&ac->guest_save, sizeof(struct state_save_t), ac)) {
        BFERROR("setup_virt failed\n");
        return LOADER_FAILURE;
    }

    if (setup_phys(&ac->guest_save_phys, ac->guest_save, ac)) {
        BFERROR("setup_phys failed\n");
        return LOADER_FAILURE;
    }

    /**
     * Notes:
     * - Done.
     */

    return 0;
}

/**
 * <!-- description -->
 *   @brief Prepare the host xsave area. The host xsave area is used to
 *     save/load state the the VMRUN does not save/load for us that is
 *     specifically handled by the xsave instruction. This does not include
 *     the host VMCB state or the state save.
 *
 * <!-- inputs/outputs -->
 *   @param ac the architecture specific context for this cpu
 *   @return Returns 0 on success
 */
int64_t
prepare_host_xsave_area(struct loader_arch_context_t *ac)
{
    if (NULL == ac) {
        BFERROR("invalid argument\n");
        return LOADER_FAILURE;
    }

    /**
     * Notes:
     * - Allocate, validate and clear the host's xsave area
     * - Get and validate the host xsave area's physical address
     */

    if (setup_virt(&ac->host_xsave, ac->page_size, ac)) {
        BFERROR("setup_virt failed\n");
        return LOADER_FAILURE;
    }

    if (setup_phys(&ac->host_xsave_phys, ac->host_xsave, ac)) {
        BFERROR("setup_phys failed\n");
        return LOADER_FAILURE;
    }

    /**
     * Notes:
     * - Done.
     */

    return 0;
}

/**
 * <!-- description -->
 *   @brief Prepare the guest xsave area. The guest xsave area is used to
 *     save/load state the the VMRUN does not save/load for us that is
 *     specifically handled by the xsave instruction. This does not include
 *     the guest VMCB state or the state save.
 *
 * <!-- inputs/outputs -->
 *   @param ac the architecture specific context for this cpu
 *   @return Returns 0 on success
 */
int64_t
prepare_guest_xsave_area(struct loader_arch_context_t *ac)
{
    if (NULL == ac) {
        BFERROR("invalid argument\n");
        return LOADER_FAILURE;
    }

    /**
     * Notes:
     * - Allocate, validate and clear the guest's xsave area
     * - Get and validate the guest xsave area's physical address
     */

    if (setup_virt(&ac->guest_xsave, ac->page_size, ac)) {
        BFERROR("setup_virt failed\n");
        return LOADER_FAILURE;
    }

    if (setup_phys(&ac->guest_xsave_phys, ac->guest_xsave, ac)) {
        BFERROR("setup_phys failed\n");
        return LOADER_FAILURE;
    }

    /**
     * Notes:
     * - Done.
     */

    return 0;
}

/**
 * <!-- description -->
 *   @brief Handles VMEXIT events. This occurs when the vmrun instruction
 *     returns and an intercept must be handled.
 *
 * <!-- inputs/outputs -->
 *   @param ac the architecture specific context for this cpu
 */
void
arch_exit_handler(struct loader_arch_context_t *ac)
{
    switch (ac->guest_vmcb->exitcode) {
        case VMEXIT_INVALID:
            arch_write_serial("invalid guest state\n");
            break;

        case VMEXIT_CPUID:
            arch_cpuid(
                &ac->guest_vmcb->rax,
                &ac->guest_save->rbx,
                &ac->guest_save->rcx,
                &ac->guest_save->rdx);

            ac->guest_vmcb->rip = ac->guest_vmcb->nrip;
            return;

        case VMEXIT_VMMCALL:
            arch_write_serial("intercepted vmmcall\n");
            ac->guest_vmcb->rip = ac->guest_vmcb->nrip;
            return;

        default:
            arch_write_serial("unhandled intercept\n");
            break;
    };

    while (1) {
    }
}

/**
 * <!-- description -->
 *   @brief This function contains all of the code that is arch specific
 *     while common between all platforms for starting the VMM. This function
 *     will call platform specific functions as needed. Unlike start_vmm,
 *     this function is called on each CPU.
 *
 * <!-- inputs/outputs -->
 *   @param cpu the id of the cpu to start
 *   @param context the common context for this cpu
 *   @param ac the architecture specific context for this cpu
 *   @return Returns 0 on success
 */
int64_t
arch_start_vmm_per_cpu(                  // --
    uint32_t const cpu,                  // --
    struct loader_context_t *context,    // --
    struct loader_arch_context_t *ac)
{
    if (0 != cpu) {
        return 0;
    }

    arch_write_serial("arch_start_vmm_per_cpu\n");

    if (NULL == context) {
        BFERROR("invalid argument\n");
        return LOADER_FAILURE;
    }

    if (NULL == ac) {
        BFERROR("invalid argument\n");
        return LOADER_FAILURE;
    }

    /**
     * TODO:
     * - We need to get the physical address bit limit value from CPUID
     *   instead of hardcoding it.
     */
    ac->page_size = 0x1000U;
    ac->physical_address_bits = 48U;
    ac->host_stack_size = 0x10000;
    ac->exit_handler = &arch_exit_handler;

    if (arch_check_hve_support()) {
        BFERROR("arch_check_hvm_support failed\n");
        return LOADER_FAILURE;
    }

    if (enable_svm()) {
        BFERROR("enable_svm failed\n");
        return LOADER_FAILURE;
    }

    if (prepare_host_vmcb(ac)) {
        BFERROR("prepare_host_vmcb failed\n");
        return LOADER_FAILURE;
    }

    if (prepare_guest_vmcb(ac)) {
        BFERROR("prepare_guest_vmcb failed\n");
        return LOADER_FAILURE;
    }

    if (prepare_host_state_save(ac)) {
        BFERROR("prepare_host_state_save failed\n");
        return LOADER_FAILURE;
    }

    if (prepare_guest_state_save(ac)) {
        BFERROR("prepare_guest_state_save failed\n");
        return LOADER_FAILURE;
    }

    if (prepare_host_xsave_area(ac)) {
        BFERROR("prepare_host_xsave_area failed\n");
        return LOADER_FAILURE;
    }

    if (prepare_guest_xsave_area(ac)) {
        BFERROR("prepare_guest_xsave_area failed\n");
        return LOADER_FAILURE;
    }

    arch_vmrun(ac);
    arch_write_serial("root OS cpu now in a VM\n");

    return 0;
}

// // clang-format off

// uint8_t *vmcb;

// vmcb = ((uint8_t *)ac->guest_vmcb);

// BFDEBUG("[0x%03x]: 0x%08x          %s\n",        0x000,  *(uint32_t *)(vmcb + 0x000), "- intercept crs");
// BFDEBUG("[0x%03x]: 0x%08x          %s\n",        0x004,  *(uint32_t *)(vmcb + 0x004), "- intercept drs");
// BFDEBUG("[0x%03x]: 0x%08x          %s\n",        0x008,  *(uint32_t *)(vmcb + 0x008), "- intercept exceptions");
// BFDEBUG("[0x%03x]: 0x%08x          %s\n",        0x00C,  *(uint32_t *)(vmcb + 0x00C), "- intercept misc1");
// BFDEBUG("[0x%03x]: 0x%08x          %s\n",        0x010,  *(uint32_t *)(vmcb + 0x010), "- intercept misc2");
// BFDEBUG("[0x%03x]: 0x%08x          %s\n",        0x014,  *(uint32_t *)(vmcb + 0x014), "- intercept misc3");
// BFDEBUG("[0x%03x]: 0x%08x          %s\n",        0x058,  *(uint32_t *)(vmcb + 0x058), "- asid");

// vmcb += 0x400;

// BFDEBUG("[0x%03x]: 0x%04x              %s\n",    0x000,  *(uint16_t *)(vmcb + 0x000), "- es selector");
// BFDEBUG("[0x%03x]: 0x%04x              %s\n",    0x002,  *(uint16_t *)(vmcb + 0x002), "- es attributes");
// BFDEBUG("[0x%03x]: 0x%08x          %s\n",        0x004,  *(uint32_t *)(vmcb + 0x004), "- es limit");
// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x008,  *(uint64_t *)(vmcb + 0x008), "- es base");
// BFDEBUG("\n");

// BFDEBUG("[0x%03x]: 0x%04x              %s\n",    0x010,  *(uint16_t *)(vmcb + 0x010), "- cs selector");
// BFDEBUG("[0x%03x]: 0x%04x              %s\n",    0x012,  *(uint16_t *)(vmcb + 0x012), "- cs attributes");
// BFDEBUG("[0x%03x]: 0x%08x          %s\n",        0x014,  *(uint32_t *)(vmcb + 0x014), "- cs limit");
// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x018,  *(uint64_t *)(vmcb + 0x018), "- cs base");
// BFDEBUG("\n");

// BFDEBUG("[0x%03x]: 0x%04x              %s\n",    0x020,  *(uint16_t *)(vmcb + 0x020), "- ss selector");
// BFDEBUG("[0x%03x]: 0x%04x              %s\n",    0x022,  *(uint16_t *)(vmcb + 0x022), "- ss attributes");
// BFDEBUG("[0x%03x]: 0x%08x          %s\n",        0x024,  *(uint32_t *)(vmcb + 0x024), "- ss limit");
// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x028,  *(uint64_t *)(vmcb + 0x028), "- ss base");
// BFDEBUG("\n");

// BFDEBUG("[0x%03x]: 0x%04x              %s\n",    0x030,  *(uint16_t *)(vmcb + 0x030), "- ds selector");
// BFDEBUG("[0x%03x]: 0x%04x              %s\n",    0x032,  *(uint16_t *)(vmcb + 0x032), "- ds attributes");
// BFDEBUG("[0x%03x]: 0x%08x          %s\n",        0x034,  *(uint32_t *)(vmcb + 0x034), "- ds limit");
// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x038,  *(uint64_t *)(vmcb + 0x038), "- ds base");
// BFDEBUG("\n");

// BFDEBUG("[0x%03x]: 0x%04x              %s\n",    0x040,  *(uint16_t *)(vmcb + 0x040), "- fs selector");
// BFDEBUG("[0x%03x]: 0x%04x              %s\n",    0x042,  *(uint16_t *)(vmcb + 0x042), "- fs attributes");
// BFDEBUG("[0x%03x]: 0x%08x          %s\n",        0x044,  *(uint32_t *)(vmcb + 0x044), "- fs limit");
// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x048,  *(uint64_t *)(vmcb + 0x048), "- fs base");
// BFDEBUG("\n");

// BFDEBUG("[0x%03x]: 0x%04x              %s\n",    0x050,  *(uint16_t *)(vmcb + 0x050), "- gs selector");
// BFDEBUG("[0x%03x]: 0x%04x              %s\n",    0x052,  *(uint16_t *)(vmcb + 0x052), "- gs attributes");
// BFDEBUG("[0x%03x]: 0x%08x          %s\n",        0x054,  *(uint32_t *)(vmcb + 0x054), "- gs limit");
// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x058,  *(uint64_t *)(vmcb + 0x058), "- gs base");
// BFDEBUG("\n");

// BFDEBUG("[0x%03x]: 0x%04x              %s\n",    0x060,  *(uint16_t *)(vmcb + 0x060), "- gdtr selector");
// BFDEBUG("[0x%03x]: 0x%04x              %s\n",    0x062,  *(uint16_t *)(vmcb + 0x062), "- gdtr attributes");
// BFDEBUG("[0x%03x]: 0x%08x          %s\n",        0x064,  *(uint32_t *)(vmcb + 0x064), "- gdtr limit");
// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x068,  *(uint64_t *)(vmcb + 0x068), "- gdtr base");
// BFDEBUG("\n");

// BFDEBUG("[0x%03x]: 0x%04x              %s\n",    0x070,  *(uint16_t *)(vmcb + 0x070), "- ldtr selector");
// BFDEBUG("[0x%03x]: 0x%04x              %s\n",    0x072,  *(uint16_t *)(vmcb + 0x072), "- ldtr attributes");
// BFDEBUG("[0x%03x]: 0x%08x          %s\n",        0x074,  *(uint32_t *)(vmcb + 0x074), "- ldtr limit");
// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x078,  *(uint64_t *)(vmcb + 0x078), "- ldtr base");
// BFDEBUG("\n");

// BFDEBUG("[0x%03x]: 0x%04x              %s\n",    0x080,  *(uint16_t *)(vmcb + 0x080), "- idtr selector");
// BFDEBUG("[0x%03x]: 0x%04x              %s\n",    0x082,  *(uint16_t *)(vmcb + 0x082), "- idtr attributes");
// BFDEBUG("[0x%03x]: 0x%08x          %s\n",        0x084,  *(uint32_t *)(vmcb + 0x084), "- idtr limit");
// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x088,  *(uint64_t *)(vmcb + 0x088), "- idtr base");
// BFDEBUG("\n");

// BFDEBUG("[0x%03x]: 0x%04x              %s\n",    0x090,  *(uint16_t *)(vmcb + 0x090), "- tr selector");
// BFDEBUG("[0x%03x]: 0x%04x              %s\n",    0x092,  *(uint16_t *)(vmcb + 0x092), "- tr attributes");
// BFDEBUG("[0x%03x]: 0x%08x          %s\n",        0x094,  *(uint32_t *)(vmcb + 0x094), "- tr limit");
// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x098,  *(uint64_t *)(vmcb + 0x098), "- tr base");
// BFDEBUG("\n");

// BFDEBUG("[0x%03x]: 0x%02x                %s\n",  0x0CB,  *(uint8_t *)(vmcb + 0x0CB), "- cpl");
// BFDEBUG("\n");

// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x0D0,  *(uint64_t *)(vmcb + 0x0D0), "- efer");
// BFDEBUG("\n");

// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x148,  *(uint64_t *)(vmcb + 0x148), "- cr4");
// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x150,  *(uint64_t *)(vmcb + 0x150), "- cr3");
// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x158,  *(uint64_t *)(vmcb + 0x158), "- cr0");
// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x160,  *(uint64_t *)(vmcb + 0x160), "- dr7");
// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x168,  *(uint64_t *)(vmcb + 0x168), "- dr6");
// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x170,  *(uint64_t *)(vmcb + 0x170), "- rflags");
// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x178,  *(uint64_t *)(vmcb + 0x178), "- rip");
// BFDEBUG("\n");

// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x1D8,  *(uint64_t *)(vmcb + 0x1D8), "- rsp");
// BFDEBUG("\n");

// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x1F8,  *(uint64_t *)(vmcb + 0x1F8), "- rax");
// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x200,  *(uint64_t *)(vmcb + 0x200), "- star");
// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x208,  *(uint64_t *)(vmcb + 0x208), "- lstar");
// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x210,  *(uint64_t *)(vmcb + 0x210), "- cstar");
// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x218,  *(uint64_t *)(vmcb + 0x218), "- sfmask");
// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x220,  *(uint64_t *)(vmcb + 0x220), "- kernel gs base");
// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x228,  *(uint64_t *)(vmcb + 0x228), "- sysenter_cs");
// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x230,  *(uint64_t *)(vmcb + 0x230), "- sysenter_esp");
// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x238,  *(uint64_t *)(vmcb + 0x238), "- sysenter_eip");
// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x240,  *(uint64_t *)(vmcb + 0x240), "- cr2");
// BFDEBUG("\n");

// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x268,  *(uint64_t *)(vmcb + 0x268), "- pat");
// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x270,  *(uint64_t *)(vmcb + 0x270), "- dbgctl");
// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x278,  *(uint64_t *)(vmcb + 0x278), "- br from");
// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x280,  *(uint64_t *)(vmcb + 0x280), "- br to");
// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x288,  *(uint64_t *)(vmcb + 0x288), "- last exception from");
// BFDEBUG("[0x%03x]: 0x%016llx  %s\n",             0x290,  *(uint64_t *)(vmcb + 0x290), "- last except to");
// BFDEBUG("\n");
