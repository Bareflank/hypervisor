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

#include <constants.h>
#include <debug.h>
#include <efi/efi_system_table.h>
#include <global_descriptor_table_register_t.h>
#include <intrinsic_lgdt.h>
#include <intrinsic_ltr.h>
#include <intrinsic_sgdt.h>
#include <intrinsic_str.h>
#include <platform.h>
#include <set_gdt_descriptor.h>
#include <tss_t.h>
#include <types.h>

/** @brief defines our custom TR attributes */
#define UEFI_TR_ATTRIB ((uint16_t)0x00000089)
/** @brief defines our custom TR limit */
#define UEFI_TR_LIMIT ((uint32_t)(sizeof(struct tss_t) - ((uint64_t)1)))

/** @brief stores the old GDT that UEFI will use */
struct global_descriptor_table_register_t g_old_gdtr = {0};

/**
 * <!-- description -->
 *   @brief Ensures that the TSS is set up properly.
 *
 * <!-- inputs/outputs -->
 *   @return Returns 0 on success, LOADER_FAILURE otherwise
 */
int64_t
setup_tss(void)
{
    int64_t ret;

    /**
     * NOTE:
     * - UEFI doesn't seem to set the TR segment. This causes a number of
     *   issues with our code so we create a new GDT that is the same as
     *   the current GDT, but with TR added.
     * - This seems to be an issue on both AMD and Intel, and also seems to
     *   be an issue on multiple systems from different vendors.
     * - One issue is that on Intel, you cannot start a VM with TR set to 0.
     *   Any attempt to do so will cause a VM entry failure.
     * - Another issue is that when you attempt to return (i.e. promote) from
     *   the microkernel, the promote logic doesn't have a TR to flip the
     *   TSS busy bit for. As a result, it has to leave the TR set to the
     *   microkernel's TR which leaks it's resources.
     * - UEFI also seems to copy the GDT from one PP to another as it starts
     *   each AP. This means that we need to cache the original GDT so that
     *   we can use it for reference. Otherwise, on other PPs, you would
     *   get the GDT you created on the BSP, which already has a TSS and it
     *   cannot be shared (due to the TSS busy bit).
     */

    struct tss_t *tss;
    struct global_descriptor_table_register_t gdtr;

    if (intrinsic_str() != ((uint16_t)0)) {

        /**
         * NOTE:
         * - Based on testing, I don't think this specific branch will
         *   actually be taken, but just in case there is a TR set, we don't
         *   need to actually execute this code.
         */

        return LOADER_SUCCESS;
    }

    if (NULLPTR == g_old_gdtr.base) {
        intrinsic_sgdt(&g_old_gdtr);
        g_old_gdtr.limit += ((uint16_t)1);
    }

    if (g_old_gdtr.limit > ((uint16_t)0xFF0)) {
        bferror("system unsupported. existing GDT is too large");
        return LOADER_FAILURE;
    }

    /**
     * NOTE:
     * - Allocate the new GDT and the new TSS. The TR will be set to the
     *   current GDT's limit. This ensures that the TR uses the first
     *   available entry in the old GDT.
     */

    gdtr.base = (uint64_t *)platform_alloc(HYPERVISOR_PAGE_SIZE);
    if (NULLPTR == gdtr.base) {
        bferror("platform_alloc failed");
        goto platform_alloc_gdt_failed;
    }

    gdtr.limit = (uint16_t)(HYPERVISOR_PAGE_SIZE - ((uint64_t)1));

    /**
     * TODO:
     * - There is an issue here. If an interrupt or exception fires, we might
     *   have a problem if UEFI's IDT is set up to use the IST when an
     *   interrupt first. Since the TR is not set, it is likely that the IDT
     *   is set up to use the stack, in which case the IST is never used,
     *   and this TSS configuration is fine. We should veryify this on
     *   different systems to prove that this will work. Otherwise, using
     *   other UEFI functions that need interrupts might fail if UEFI tries
     *   to add a TR to their GDT but ours is loaded and the TSS's do not
     *   match.
     */

    tss = (struct tss_t *)platform_alloc(HYPERVISOR_PAGE_SIZE);
    if (NULLPTR == tss) {
        bferror("platform_alloc failed");
        goto platform_alloc_tss_failed;
    }

    tss->iomap = ((uint16_t)sizeof(struct tss_t));

    /**
     * NOTE:
     * - Set up the new GDT. To do this, all we need to do is copy over the
     *   old GDT and then add the TSS.
     */

    g_st->BootServices->CopyMem(gdtr.base, g_old_gdtr.base, g_old_gdtr.limit);

    set_gdt_descriptor(      // --
        &gdtr,               // --
        g_old_gdtr.limit,    // --
        (uint64_t)tss,       // --
        UEFI_TR_LIMIT,       // --
        UEFI_TR_ATTRIB);

    /**
     * NOTE:
     * - Now that the new GDT is set up, we can load it as well as the TR
     *   segment which should fixes the above identified issues. Note that
     *   we do not need to load any other segment registers are they are
     *   all identical.
     */

    intrinsic_lgdt(&gdtr);
    intrinsic_ltr(g_old_gdtr.limit);

    return LOADER_SUCCESS;

platform_alloc_tss_failed:
    platform_free(gdtr.base, HYPERVISOR_PAGE_SIZE);
platform_alloc_gdt_failed:

    return LOADER_FAILURE;
}
