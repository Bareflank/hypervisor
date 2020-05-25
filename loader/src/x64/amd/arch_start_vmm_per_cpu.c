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

/**
 * <!-- description -->
 *   @brief Enable Secure Virtual Machine support. This turns on the
 *     ability to use the VMRUN, VMLOAD and VMSAVE instructions, as well
 *     as some other support instructions like stgi and clgi.
 */
int64_t
enable_svm(void)
{
    /**
     * TODO:
     * - We should not be reading EFER more than once, so we really should
     *   read this into the context before we start and then use it as needed.
     */

    uint64_t efer = arch_rdmsr(MSR_EFER);

    if ((efer & MSR_EFER_SVME) != 0) {
        BFERROR("SVM is already running. Is another hypervisor running?\n");
        return FAILURE;
    }

    arch_wrmsr(MSR_EFER, efer | MSR_EFER_SVME);
    return 0;
}

/**
 * <!-- description -->
 *   @brief Prepare the host VMCB. Once a VMRUN is performed, the host
 *     and the guest will diverge into two different states. The VMRUN
 *     instruction does not save all of the state that the host requires
 *     similar to how it does not save/load all of the guest state.
 *     This function allocates space for the missing host state.
 *
 * <!-- inputs/outputs -->
 *   @param arch_context the architecture specific context for this cpu
 *   @return Returns 0 on success
 */
int64_t
prepare_host_vmcb(struct loader_arch_context_t *arch_context)
{
    uintptr_t virt;
    uintptr_t phys;

    if (NULL == arch_context) {
        BFERROR("invalid argument\n");
        return FAILURE;
    }

    virt = (uintptr_t)platform_alloc(sizeof(struct vmcb_t));
    if (0U == virt) {
        BFERROR("failed to allocate host vmcb\n");
        return FAILURE;
    }

    phys = platform_virt_to_phys(virt);
    if (0U == phys) {
        BFERROR("failed to get the host vmcb's physical address\n");
        platform_free((void *)virt, sizeof(struct vmcb_t));
        return FAILURE;
    }

    if (check_page_aligned(virt, arch_context)) {
        BFERROR("check_page_aligned failed\n");
        platform_free((void *)virt, sizeof(struct vmcb_t));
        return FAILURE;
    }

    if (check_page_aligned(phys, arch_context)) {
        BFERROR("check_page_aligned failed\n");
        platform_free((void *)virt, sizeof(struct vmcb_t));
        return FAILURE;
    }

    if (check_canonical(virt, arch_context)) {
        BFERROR("check_canonical failed\n");
        platform_free((void *)virt, sizeof(struct vmcb_t));
        return FAILURE;
    }

    if (check_valid_physical(phys, arch_context)) {
        BFERROR("check_valid_physical failed\n");
        platform_free((void *)virt, sizeof(struct vmcb_t));
        return FAILURE;
    }

    arch_context->host_vmcb_virt = (struct vmcb_t *)virt;
    arch_context->host_vmcb_phys = phys;

    return 0;
}

/**
 * <!-- description -->
 *   @brief Prepare the guest VMCB. The guest VMCB is used to store all
 *     of the state associated with the guest VM. This function allocates
 *     space for this state.
 *
 * <!-- inputs/outputs -->
 *   @param arch_context the architecture specific context for this cpu
 *   @return Returns 0 on success
 */
int64_t
prepare_guest_vmcb(struct loader_arch_context_t *arch_context)
{
    uintptr_t virt;
    uintptr_t phys;

    if (NULL == arch_context) {
        BFERROR("invalid argument\n");
        return FAILURE;
    }

    virt = (uintptr_t)platform_alloc(sizeof(struct vmcb_t));
    if (0U == virt) {
        BFERROR("failed to allocate guest vmcb\n");
        return FAILURE;
    }

    phys = platform_virt_to_phys(virt);
    if (0U == phys) {
        BFERROR("failed to get the guest vmcb's physical address\n");
        platform_free((void *)virt, sizeof(struct vmcb_t));
        return FAILURE;
    }

    if (check_page_aligned(virt, arch_context)) {
        BFERROR("check_page_aligned failed\n");
        platform_free((void *)virt, sizeof(struct vmcb_t));
        return FAILURE;
    }

    if (check_page_aligned(phys, arch_context)) {
        BFERROR("check_page_aligned failed\n");
        platform_free((void *)virt, sizeof(struct vmcb_t));
        return FAILURE;
    }

    if (check_canonical(virt, arch_context)) {
        BFERROR("check_canonical failed\n");
        platform_free((void *)virt, sizeof(struct vmcb_t));
        return FAILURE;
    }

    if (check_valid_physical(phys, arch_context)) {
        BFERROR("check_valid_physical failed\n");
        platform_free((void *)virt, sizeof(struct vmcb_t));
        return FAILURE;
    }

    arch_context->guest_vmcb_virt = (struct vmcb_t *)virt;
    arch_context->guest_vmcb_phys = phys;

    return 0;
}

/**
 * <!-- description -->
 *   @brief Prepare the host state save. The host state save is used
 *     by the VMRUN instruction to store state associated with the
 *     host. This state does not include the state that is saved using
 *     the vmsave instruction, which is why we also have a host VMCB.
 *     This function allocates the space for the host state save.
 *
 * <!-- inputs/outputs -->
 *   @param arch_context the architecture specific context for this cpu
 *   @return Returns 0 on success
 */
int64_t
prepare_host_state_save(struct loader_arch_context_t *arch_context)
{
    uintptr_t virt;
    uintptr_t phys;

    if (NULL == arch_context) {
        BFERROR("invalid argument\n");
        return FAILURE;
    }

    virt = (uintptr_t)platform_alloc(arch_context->page_size);
    if (0U == virt) {
        BFERROR("failed to allocate host state save\n");
        return FAILURE;
    }

    phys = platform_virt_to_phys(virt);
    if (0U == phys) {
        BFERROR("failed to get the host state save's physical address\n");
        platform_free((void *)virt, arch_context->page_size);
        return FAILURE;
    }

    if (check_page_aligned(virt, arch_context)) {
        BFERROR("check_page_aligned failed\n");
        platform_free((void *)virt, arch_context->page_size);
        return FAILURE;
    }

    if (check_page_aligned(phys, arch_context)) {
        BFERROR("check_page_aligned failed\n");
        platform_free((void *)virt, arch_context->page_size);
        return FAILURE;
    }

    if (check_canonical(virt, arch_context)) {
        BFERROR("check_canonical failed\n");
        platform_free((void *)virt, arch_context->page_size);
        return FAILURE;
    }

    if (check_valid_physical(phys, arch_context)) {
        BFERROR("check_valid_physical failed\n");
        platform_free((void *)virt, arch_context->page_size);
        return FAILURE;
    }

    arch_context->host_state_save_virt = (void *)virt;
    arch_context->host_state_save_phys = phys;

    return 0;
}

/**
 * <!-- description -->
 *   @brief Configure the host VMCB. Once a VMRUN is performed, the host
 *     and the guest will diverge into two different states. The VMRUN
 *     instruction does not save all of the state that the host requires
 *     similar to how it does not save/load all of the guest state.
 *     This function uses the vmsave instruction to store the missing
 *     host state.
 *
 * <!-- inputs/outputs -->
 *   @param arch_context the architecture specific context for this cpu
 *   @return Returns 0 on success
 */
int64_t
configure_host_vmcb(struct loader_arch_context_t *arch_context)
{
    if (NULL == arch_context) {
        BFERROR("invalid argument\n");
        return FAILURE;
    }

    if (NULL == arch_context->host_vmcb_virt) {
        BFERROR("invalid host vmcb virtual address\n");
        return FAILURE;
    }

    if (0U == arch_context->host_vmcb_phys) {
        BFERROR("invalid host vmcb physical address\n");
        return FAILURE;
    }

    /**
     * Note:
     * - Get and store the FS, GS, TR and LDTR
     * - Get and store the KernelGsBase
     * - Get and store the STAR, LSTAR, CSTAR, SFMASK
     * - Get and store the SYSENTER_CS, SYSENTER_ESP, SYSENTER_EIP
     */

    arch_vmsave(arch_context->host_vmcb_phys);

    return 0;
}

/**
 * <!-- description -->
 *   @brief Configure the guest VMCB. The guest VMCB is used to store all
 *     of the state associated with the guest VM. This function configures
 *     this state.
 *
 * <!-- inputs/outputs -->
 *   @param arch_context the architecture specific context for this cpu
 *   @return Returns 0 on success
 */
int64_t
configure_guest_vmcb(struct loader_arch_context_t *arch_context)
{
    struct vmcb_t *vmcb = NULL;

    uint16_t es_index = 0;
    uint16_t cs_index = 0;
    uint16_t ss_index = 0;
    uint16_t ds_index = 0;

    struct global_descriptor_table_register gdtr = {0};
    struct interrupt_descriptor_table_register idtr = {0};

    if (NULL == arch_context) {
        BFERROR("invalid argument\n");
        return FAILURE;
    }

    if (NULL == arch_context->guest_vmcb_virt) {
        BFERROR("invalid guest vmcb virtual address\n");
        return FAILURE;
    }

    if (0U == arch_context->guest_vmcb_phys) {
        BFERROR("invalid guest vmcb physical address\n");
        return FAILURE;
    }

    vmcb = arch_context->guest_vmcb_virt;

    /**
     * TODO: We will need to turn on more than just this inside the default
     *       extension including the SVM control bit, EFER MSR, remaining
     *       VM instructions, etc... In general, this code belongs in the
     *       extension and not in the kernel.
     */

    vmcb->intercept_instruction1 |= VMCB_INTERCEPT_INSTRUCTION1_CPUID;
    vmcb->intercept_instruction1 |= VMCB_INTERCEPT_INSTRUCTION1_VMRUN;

    /**
     * TODO: We need to determine what the supported values for ASID are
     *       from CPUID, and we will need a "vm" structure in the kernel
     *       that we can use to give out these values based on the max
     *       total number of supported VMs. For now, we just set this to
     *       1. Also note that this is the same as VPID, so Intel will
     *       need the same thing. The current code gives each vCPU its own
     *       VPID which is not right. Instead, each VM should have its
     *       own VPID/ASID so that you can flush the TLB using remote
     *       instructions like the new INVLPGB that AMD is adding. Also
     *       note that this code belongs in the extension and not in the
     *       kernel as the kernel will have concept of a VM.
     */
    vmcb->tlb_control = 1;

    /**
     * Note:
     * - Get the GDTR and the IDTR. These will be used to set up some
     *   additional fields in the VMCB.
     */

    arch_sgdt(&gdtr);
    arch_sidt(&idtr);

    vmcb->gdtr_limit = gdtr.limit;
    vmcb->gdtr_base = (uintptr_t)gdtr.base;
    vmcb->idtr_limit = idtr.limit;
    vmcb->idtr_base = (uintptr_t)idtr.base;

    if (check_canonical(vmcb->gdtr_base, arch_context)) {
        BFERROR("gdtr base not canonical: 0x%" PRIx64 "\n", vmcb->gdtr_base);
        return FAILURE;
    }

    if (check_canonical(vmcb->idtr_base, arch_context)) {
        BFERROR("idtr base not canonical: 0x%" PRIx64 "\n", vmcb->idtr_base);
        return FAILURE;
    }

    BFDEBUG("gdtr_limit: 0x%x\n", vmcb->gdtr_limit);
    BFDEBUG("gdtr_base: 0x%" PRIx64 "\n", vmcb->gdtr_base);
    BFDEBUG("idtr_limit: 0x%x\n", vmcb->idtr_limit);
    BFDEBUG("idtr_base: 0x%" PRIx64 "\n", vmcb->idtr_base);

    /**
     * Note:
     * - Get segment selectors.
     */

    vmcb->es_selector = arch_reades();
    vmcb->cs_selector = arch_readcs();
    vmcb->ss_selector = arch_readss();
    vmcb->ds_selector = arch_readds();

    BFDEBUG("es_selector: 0x%x\n", vmcb->es_selector);
    BFDEBUG("cs_selector: 0x%x\n", vmcb->cs_selector);
    BFDEBUG("ss_selector: 0x%x\n", vmcb->ss_selector);
    BFDEBUG("ds_selector: 0x%x\n", vmcb->ds_selector);

    /**
     * Note:
     * - Get segment descriptor indexes. This is needed because the segment
     *   selector has additional bits for privilege levels, etc.., so we
     *   need to remove these to get access to the actual indexes into the
     *   global descriptor table.
     */

    es_index = vmcb->es_selector >> 3U;
    cs_index = vmcb->cs_selector >> 3U;
    ss_index = vmcb->ss_selector >> 3U;
    ds_index = vmcb->ds_selector >> 3U;

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

    vmcb->es_attrib = get_segment_descriptor_attrib(&gdtr, es_index);
    vmcb->es_limit = get_segment_descriptor_limit(&gdtr, es_index);
    vmcb->es_base = get_segment_descriptor_base(&gdtr, es_index);
    vmcb->cs_attrib = get_segment_descriptor_attrib(&gdtr, cs_index);
    vmcb->cs_limit = get_segment_descriptor_limit(&gdtr, cs_index);
    vmcb->cs_base = get_segment_descriptor_base(&gdtr, cs_index);
    vmcb->ss_attrib = get_segment_descriptor_attrib(&gdtr, ss_index);
    vmcb->ss_limit = get_segment_descriptor_limit(&gdtr, ss_index);
    vmcb->ss_base = get_segment_descriptor_base(&gdtr, ss_index);
    vmcb->ds_attrib = get_segment_descriptor_attrib(&gdtr, ds_index);
    vmcb->ds_limit = get_segment_descriptor_limit(&gdtr, ds_index);
    vmcb->ds_base = get_segment_descriptor_base(&gdtr, ds_index);

    if (0xFFFFFFFFU == vmcb->es_attrib) {
        BFERROR("failed to get the es segment's attributes\n");
        return FAILURE;
    }

    if (0xFFFFFFFFU == vmcb->cs_attrib) {
        BFERROR("failed to get the cs segment's attributes\n");
        return FAILURE;
    }

    if (0xFFFFFFFFU == vmcb->ss_attrib) {
        BFERROR("failed to get the ss segment's attributes\n");
        return FAILURE;
    }

    if (0xFFFFFFFFU == vmcb->ds_attrib) {
        BFERROR("failed to get the ds segment's attributes\n");
        return FAILURE;
    }

    if (0U == vmcb->es_limit) {
        BFERROR("failed to get the es segment's limit\n");
        return FAILURE;
    }

    if (0U == vmcb->cs_limit) {
        BFERROR("failed to get the cs segment's limit\n");
        return FAILURE;
    }

    if (0U == vmcb->ss_limit) {
        BFERROR("failed to get the ss segment's limit\n");
        return FAILURE;
    }

    if (0U == vmcb->ds_limit) {
        BFERROR("failed to get the ds segment's limit\n");
        return FAILURE;
    }

    if (0xFFFFFFFFU == vmcb->es_base) {
        BFERROR("failed to get the es segment's base address\n");
        return FAILURE;
    }

    if (0xFFFFFFFFU == vmcb->cs_base) {
        BFERROR("failed to get the cs segment's base address\n");
        return FAILURE;
    }

    if (0xFFFFFFFFU == vmcb->ss_base) {
        BFERROR("failed to get the ss segment's base address\n");
        return FAILURE;
    }

    if (0xFFFFFFFFU == vmcb->ds_base) {
        BFERROR("failed to get the ds segment's base address\n");
        return FAILURE;
    }

    if (check_canonical(vmcb->es_base, arch_context)) {
        BFERROR("check_canonical failed\n");
        return FAILURE;
    }

    if (check_canonical(vmcb->cs_base, arch_context)) {
        BFERROR("check_canonical failed\n");
        return FAILURE;
    }

    if (check_canonical(vmcb->ss_base, arch_context)) {
        BFERROR("check_canonical failed\n");
        return FAILURE;
    }

    if (check_canonical(vmcb->ds_base, arch_context)) {
        BFERROR("check_canonical failed\n");
        return FAILURE;
    }

    BFDEBUG("es_attrib: 0x%x\n", vmcb->es_attrib);
    BFDEBUG("es_limit: 0x%x\n", vmcb->es_limit);
    BFDEBUG("es_base: 0x%" PRIx64 "\n", vmcb->es_base);
    BFDEBUG("cs_attrib: 0x%x\n", vmcb->cs_attrib);
    BFDEBUG("cs_limit: 0x%x\n", vmcb->cs_limit);
    BFDEBUG("cs_base: 0x%" PRIx64 "\n", vmcb->cs_base);
    BFDEBUG("ss_attrib: 0x%x\n", vmcb->ss_attrib);
    BFDEBUG("ss_limit: 0x%x\n", vmcb->ss_limit);
    BFDEBUG("ss_base: 0x%" PRIx64 "\n", vmcb->ss_base);
    BFDEBUG("ds_attrib: 0x%x\n", vmcb->ds_attrib);
    BFDEBUG("ds_limit: 0x%x\n", vmcb->ds_limit);
    BFDEBUG("ds_base: 0x%" PRIx64 "\n", vmcb->ds_base);

    /**
     * Note:
     * - Get the VMCB's model specific registers.
     */

    vmcb->efer = arch_rdmsr(MSR_EFER);
    vmcb->g_pat = arch_rdmsr(MSR_PAT);
    vmcb->dbgctl = arch_rdmsr(MSR_DEBUGCTL);

    if ((vmcb->efer & MSR_EFER_SVME) == 0) {
        BFERROR("svme has not been enabled: 0x%" PRIx64 "\n", vmcb->efer);
        return FAILURE;
    }

    if (0U == vmcb->g_pat) {
        BFERROR("invalid PAT: 0x%" PRIx64 "\n", vmcb->g_pat);
        return FAILURE;
    }

    BFDEBUG("efer: 0x%" PRIx64 "\n", vmcb->efer);
    BFDEBUG("g_pat: 0x%" PRIx64 "\n", vmcb->g_pat);
    BFDEBUG("dbgctl: 0x%" PRIx64 "\n", vmcb->dbgctl);

    /**
     * Note:
     * - Get the VMCB's control registers.
     */

    vmcb->cr0 = arch_readcr0();
    vmcb->cr2 = arch_readcr2();
    vmcb->cr3 = arch_readcr3();
    vmcb->cr4 = arch_readcr4();

    if (check_valid_physical(vmcb->cr3, arch_context)) {
        BFERROR("check_valid_physical failed\n");
        return FAILURE;
    }

    BFDEBUG("cr0: 0x%" PRIx64 "\n", vmcb->cr0);
    BFDEBUG("cr2: 0x%" PRIx64 "\n", vmcb->cr2);
    BFDEBUG("cr3: 0x%" PRIx64 "\n", vmcb->cr3);
    BFDEBUG("cr4: 0x%" PRIx64 "\n", vmcb->cr4);

    /**
     * Note:
     * - Get the VMCB's debug registers.
     */

    vmcb->dr6 = arch_readdr6();
    vmcb->dr7 = arch_readdr7();

    BFDEBUG("dr6: 0x%" PRIx64 "\n", vmcb->dr6);
    BFDEBUG("dr7: 0x%" PRIx64 "\n", vmcb->dr7);

    /**
     * Note:
     * - Get and store the FS, GS, TR and LDTR
     * - Get and store the KernelGsBase
     * - Get and store the STAR, LSTAR, CSTAR, SFMASK
     * - Get and store the SYSENTER_CS, SYSENTER_ESP, SYSENTER_EIP
     */

    arch_vmsave(arch_context->guest_vmcb_phys);

    return 0;
}

/**
 * <!-- description -->
 *   @brief Configure the host state save. The host state save is used
 *     by the VMRUN instruction to store state associated with the
 *     host. This state does not include the state that is saved using
 *     the vmsave instruction, which is why we also have a host VMCB.
 *     This function tells the hardware where to find this state save.
 *
 * <!-- inputs/outputs -->
 *   @param arch_context the architecture specific context for this cpu
 *   @return Returns 0 on success
 */
int64_t
configure_host_state_save(struct loader_arch_context_t *arch_context)
{
    if (NULL == arch_context) {
        BFERROR("invalid argument\n");
        return FAILURE;
    }

    if (NULL == arch_context->host_state_save_virt) {
        BFERROR("invalid host state save virtual address\n");
        return FAILURE;
    }

    if (0U == arch_context->host_state_save_phys) {
        BFERROR("invalid host state save physical address\n");
        return FAILURE;
    }

    /**
     * Note:
     * - Set the host state save area for this CPU.
     */

    arch_wrmsr(MSR_VM_HSAVE_PA, arch_context->host_state_save_phys);

    return 0;
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
 *   @param arch_context the architecture specific context for this cpu
 *   @return Returns 0 on success
 */
int64_t
arch_start_vmm_per_cpu(                  // --
    uint32_t const cpu,                  // --
    struct loader_context_t *context,    // --
    struct loader_arch_context_t *arch_context)
{
    if (NULL == context) {
        BFERROR("invalid argument\n");
        return FAILURE;
    }

    if (NULL == arch_context) {
        BFERROR("invalid argument\n");
        return FAILURE;
    }

    /**
     * TODO:
     * - We need to get the physical address bit limit value from CPUID
     *   instead of hardcoding it.
     */
    arch_context->page_size = 0x1000U;
    arch_context->physical_address_bits = 48U;

    if (arch_check_hve_support()) {
        BFERROR("arch_check_hve_support failed\n");
        return FAILURE;
    }

    if (enable_svm()) {
        BFERROR("enable_svm failed\n");
        return FAILURE;
    }

    if (prepare_host_vmcb(arch_context)) {
        BFERROR("prepare_host_vmcb failed\n");
        return FAILURE;
    }

    if (prepare_guest_vmcb(arch_context)) {
        BFERROR("prepare_guest_vmcb failed\n");
        return FAILURE;
    }

    if (prepare_host_state_save(arch_context)) {
        BFERROR("prepare_host_state_save failed\n");
        return FAILURE;
    }

    if (configure_host_vmcb(arch_context)) {
        BFERROR("configure_host_vmcb failed\n");
        return FAILURE;
    }

    if (configure_guest_vmcb(arch_context)) {
        BFERROR("configure_guest_vmcb failed\n");
        return FAILURE;
    }

    if (configure_host_state_save(arch_context)) {
        BFERROR("configure_host_state_save failed\n");
        return FAILURE;
    }

    // uint64_t rflags;              ///< offset 0x0570
    // uint64_t rip;                 ///< offset 0x0578
    // uint64_t rsp;                 ///< offset 0x05D8
    // uint64_t rax;                 ///< offset 0x05F8

    BFDEBUG("starting hypervisor on cpu: %u\n", cpu);

    return 0;
}
