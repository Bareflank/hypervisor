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
#include <esr_default.h>
#include <esr_df.h>
#include <esr_gpf.h>
#include <esr_nmi.h>
#include <esr_pf.h>
#include <free_root_vp_state.h>
#include <get_gdt_descriptor_attrib.h>
#include <get_gdt_descriptor_base.h>
#include <get_gdt_descriptor_limit.h>
#include <intrinsic_scs.h>
#include <intrinsic_sds.h>
#include <intrinsic_ses.h>
#include <intrinsic_sfs.h>
#include <intrinsic_sgdt.h>
#include <intrinsic_sgs.h>
#include <intrinsic_sidt.h>
#include <intrinsic_sldtr.h>
#include <intrinsic_sss.h>
#include <intrinsic_str.h>
#include <platform.h>
#include <promote.h>
#include <state_save_t.h>
#include <types.h>

#ifdef _MSC_VER
#pragma warning(disable : 4152)
#endif

/**
 * <!-- description -->
 *   @brief The function's main purpose is to save state from a root VP.
 *     The root VP is the thing executing the root VM's operating system
 *     (i.e., the kernel running this driver) for a specific processor.
 *     When the microkernel is started, it will overwrite this state, and
 *     then it will eventually take the state saved by this function and
 *     use it to run the OS inside a VM, in effect, demoting the currently
 *     running OS.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_state where to save the newly set up state to
 *   @return LOADER_SUCCESS on success, LOADER_FAILURE on failure.
 */
NODISCARD int64_t
alloc_and_copy_root_vp_state(struct state_save_t **const pmut_state) NOEXCEPT
{
    /**************************************************************************/
    /* Allocate the resulting state                                           */
    /**************************************************************************/

    *pmut_state = (struct state_save_t *)platform_alloc(HYPERVISOR_PAGE_SIZE);
    if (NULLPTR == *pmut_state) {
        bferror("platform_alloc failed");
        goto platform_alloc_state_failed;
    }

    /**************************************************************************/
    /* Descriptor Table Information                                           */
    /**************************************************************************/

    intrinsic_sgdt(&(*pmut_state)->gdtr);
    intrinsic_sidt(&(*pmut_state)->idtr);

    (*pmut_state)->es_selector = intrinsic_ses();

    get_gdt_descriptor_attrib(
        &(*pmut_state)->gdtr, (*pmut_state)->es_selector, &(*pmut_state)->es_attrib);
    get_gdt_descriptor_limit(
        &(*pmut_state)->gdtr, (*pmut_state)->es_selector, &(*pmut_state)->es_limit);
    get_gdt_descriptor_base(
        &(*pmut_state)->gdtr, (*pmut_state)->es_selector, &(*pmut_state)->es_base);

    (*pmut_state)->cs_selector = intrinsic_scs();

    get_gdt_descriptor_attrib(
        &(*pmut_state)->gdtr, (*pmut_state)->cs_selector, &(*pmut_state)->cs_attrib);
    get_gdt_descriptor_limit(
        &(*pmut_state)->gdtr, (*pmut_state)->cs_selector, &(*pmut_state)->cs_limit);
    get_gdt_descriptor_base(
        &(*pmut_state)->gdtr, (*pmut_state)->cs_selector, &(*pmut_state)->cs_base);

    (*pmut_state)->ss_selector = intrinsic_sss();

    get_gdt_descriptor_attrib(
        &(*pmut_state)->gdtr, (*pmut_state)->ss_selector, &(*pmut_state)->ss_attrib);
    get_gdt_descriptor_limit(
        &(*pmut_state)->gdtr, (*pmut_state)->ss_selector, &(*pmut_state)->ss_limit);
    get_gdt_descriptor_base(
        &(*pmut_state)->gdtr, (*pmut_state)->ss_selector, &(*pmut_state)->ss_base);

    (*pmut_state)->ds_selector = intrinsic_sds();

    get_gdt_descriptor_attrib(
        &(*pmut_state)->gdtr, (*pmut_state)->ds_selector, &(*pmut_state)->ds_attrib);
    get_gdt_descriptor_limit(
        &(*pmut_state)->gdtr, (*pmut_state)->ds_selector, &(*pmut_state)->ds_limit);
    get_gdt_descriptor_base(
        &(*pmut_state)->gdtr, (*pmut_state)->ds_selector, &(*pmut_state)->ds_base);

    (*pmut_state)->fs_selector = intrinsic_sfs();

    get_gdt_descriptor_attrib(
        &(*pmut_state)->gdtr, (*pmut_state)->fs_selector, &(*pmut_state)->fs_attrib);
    get_gdt_descriptor_limit(
        &(*pmut_state)->gdtr, (*pmut_state)->fs_selector, &(*pmut_state)->fs_limit);
    get_gdt_descriptor_base(
        &(*pmut_state)->gdtr, (*pmut_state)->fs_selector, &(*pmut_state)->fs_base);

    (*pmut_state)->gs_selector = intrinsic_sgs();

    get_gdt_descriptor_attrib(
        &(*pmut_state)->gdtr, (*pmut_state)->gs_selector, &(*pmut_state)->gs_attrib);
    get_gdt_descriptor_limit(
        &(*pmut_state)->gdtr, (*pmut_state)->gs_selector, &(*pmut_state)->gs_limit);
    get_gdt_descriptor_base(
        &(*pmut_state)->gdtr, (*pmut_state)->gs_selector, &(*pmut_state)->gs_base);

    (*pmut_state)->ldtr_selector = intrinsic_sldtr();

    get_gdt_descriptor_attrib(
        &(*pmut_state)->gdtr, (*pmut_state)->ldtr_selector, &(*pmut_state)->ldtr_attrib);
    get_gdt_descriptor_limit(
        &(*pmut_state)->gdtr, (*pmut_state)->ldtr_selector, &(*pmut_state)->ldtr_limit);
    get_gdt_descriptor_base(
        &(*pmut_state)->gdtr, (*pmut_state)->ldtr_selector, &(*pmut_state)->ldtr_base);

    (*pmut_state)->tr_selector = intrinsic_str();

    get_gdt_descriptor_attrib(
        &(*pmut_state)->gdtr, (*pmut_state)->tr_selector, &(*pmut_state)->tr_attrib);
    get_gdt_descriptor_limit(
        &(*pmut_state)->gdtr, (*pmut_state)->tr_selector, &(*pmut_state)->tr_limit);
    get_gdt_descriptor_base(
        &(*pmut_state)->gdtr, (*pmut_state)->tr_selector, &(*pmut_state)->tr_base);

    /**************************************************************************/
    /* Handlers                                                               */
    /**************************************************************************/

    (*pmut_state)->promote_handler = (void *)&promote;
    (*pmut_state)->esr_default_handler = (void *)&esr_default;
    (*pmut_state)->esr_df_handler = (void *)&esr_df;
    (*pmut_state)->esr_gpf_handler = (void *)&esr_gpf;
    (*pmut_state)->esr_nmi_handler = (void *)&esr_nmi;
    (*pmut_state)->esr_pf_handler = (void *)&esr_pf;

    return LOADER_SUCCESS;

platform_alloc_state_failed:

    free_root_vp_state(pmut_state);
    return LOADER_FAILURE;
}

#ifdef _MSC_VER
#pragma warning(default : 4152)
#endif
