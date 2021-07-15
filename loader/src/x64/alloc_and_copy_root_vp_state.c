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
#include <esr_default.h>
#include <esr_df.h>
#include <esr_gpf.h>
#include <esr_nmi.h>
#include <esr_pf.h>
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
 *   @param state where to save the newly set up state to
 *   @return LOADER_SUCCESS on success, LOADER_FAILURE on failure.
 */
int64_t
alloc_and_copy_root_vp_state(struct state_save_t **const state)
{
    int64_t ret;

    /**************************************************************************/
    /* Allocate the resulting state                                           */
    /**************************************************************************/

    *state = (struct state_save_t *)platform_alloc(HYPERVISOR_PAGE_SIZE);
    if (((void *)0) == *state) {
        bferror("platform_alloc failed");
        goto platform_alloc_state_failed;
    }

    /**************************************************************************/
    /* Descriptor Table Information                                           */
    /**************************************************************************/

    intrinsic_sgdt(&(*state)->gdtr);
    intrinsic_sidt(&(*state)->idtr);

    (*state)->es_selector = intrinsic_ses();

    ret = get_gdt_descriptor_attrib(&(*state)->gdtr, (*state)->es_selector, &(*state)->es_attrib);
    if (ret) {
        bferror("get_gdt_descriptor_attrib failed");
        goto set_descriptor_failed;
    }

    ret = get_gdt_descriptor_limit(&(*state)->gdtr, (*state)->es_selector, &(*state)->es_limit);
    if (ret) {
        bferror("get_gdt_descriptor_limit failed");
        goto set_descriptor_failed;
    }

    ret = get_gdt_descriptor_base(&(*state)->gdtr, (*state)->es_selector, &(*state)->es_base);
    if (ret) {
        bferror("get_gdt_descriptor_base failed");
        goto set_descriptor_failed;
    }

    (*state)->cs_selector = intrinsic_scs();

    ret = get_gdt_descriptor_attrib(&(*state)->gdtr, (*state)->cs_selector, &(*state)->cs_attrib);
    if (ret) {
        bferror("get_gdt_descriptor_attrib failed");
        goto set_descriptor_failed;
    }

    ret = get_gdt_descriptor_limit(&(*state)->gdtr, (*state)->cs_selector, &(*state)->cs_limit);
    if (ret) {
        bferror("get_gdt_descriptor_limit failed");
        goto set_descriptor_failed;
    }

    ret = get_gdt_descriptor_base(&(*state)->gdtr, (*state)->cs_selector, &(*state)->cs_base);
    if (ret) {
        bferror("get_gdt_descriptor_base failed");
        goto set_descriptor_failed;
    }

    (*state)->ss_selector = intrinsic_sss();

    ret = get_gdt_descriptor_attrib(&(*state)->gdtr, (*state)->ss_selector, &(*state)->ss_attrib);
    if (ret) {
        bferror("get_gdt_descriptor_attrib failed");
        goto set_descriptor_failed;
    }

    ret = get_gdt_descriptor_limit(&(*state)->gdtr, (*state)->ss_selector, &(*state)->ss_limit);
    if (ret) {
        bferror("get_gdt_descriptor_limit failed");
        goto set_descriptor_failed;
    }

    ret = get_gdt_descriptor_base(&(*state)->gdtr, (*state)->ss_selector, &(*state)->ss_base);
    if (ret) {
        bferror("get_gdt_descriptor_base failed");
        goto set_descriptor_failed;
    }

    (*state)->ds_selector = intrinsic_sds();

    ret = get_gdt_descriptor_attrib(&(*state)->gdtr, (*state)->ds_selector, &(*state)->ds_attrib);
    if (ret) {
        bferror("get_gdt_descriptor_attrib failed");
        goto set_descriptor_failed;
    }

    ret = get_gdt_descriptor_limit(&(*state)->gdtr, (*state)->ds_selector, &(*state)->ds_limit);
    if (ret) {
        bferror("get_gdt_descriptor_limit failed");
        goto set_descriptor_failed;
    }

    ret = get_gdt_descriptor_base(&(*state)->gdtr, (*state)->ds_selector, &(*state)->ds_base);
    if (ret) {
        bferror("get_gdt_descriptor_base failed");
        goto set_descriptor_failed;
    }

    (*state)->fs_selector = intrinsic_sfs();

    ret = get_gdt_descriptor_attrib(&(*state)->gdtr, (*state)->fs_selector, &(*state)->fs_attrib);
    if (ret) {
        bferror("get_gdt_descriptor_attrib failed");
        goto set_descriptor_failed;
    }

    ret = get_gdt_descriptor_limit(&(*state)->gdtr, (*state)->fs_selector, &(*state)->fs_limit);
    if (ret) {
        bferror("get_gdt_descriptor_limit failed");
        goto set_descriptor_failed;
    }

    ret = get_gdt_descriptor_base(&(*state)->gdtr, (*state)->fs_selector, &(*state)->fs_base);
    if (ret) {
        bferror("get_gdt_descriptor_base failed");
        goto set_descriptor_failed;
    }

    (*state)->gs_selector = intrinsic_sgs();

    ret = get_gdt_descriptor_attrib(&(*state)->gdtr, (*state)->gs_selector, &(*state)->gs_attrib);
    if (ret) {
        bferror("get_gdt_descriptor_attrib failed");
        goto set_descriptor_failed;
    }

    ret = get_gdt_descriptor_limit(&(*state)->gdtr, (*state)->gs_selector, &(*state)->gs_limit);
    if (ret) {
        bferror("get_gdt_descriptor_limit failed");
        goto set_descriptor_failed;
    }

    ret = get_gdt_descriptor_base(&(*state)->gdtr, (*state)->gs_selector, &(*state)->gs_base);
    if (ret) {
        bferror("get_gdt_descriptor_base failed");
        goto set_descriptor_failed;
    }

    (*state)->ldtr_selector = intrinsic_sldtr();

    ret =
        get_gdt_descriptor_attrib(&(*state)->gdtr, (*state)->ldtr_selector, &(*state)->ldtr_attrib);
    if (ret) {
        bferror("get_gdt_descriptor_attrib failed");
        goto set_descriptor_failed;
    }

    ret = get_gdt_descriptor_limit(&(*state)->gdtr, (*state)->ldtr_selector, &(*state)->ldtr_limit);
    if (ret) {
        bferror("get_gdt_descriptor_limit failed");
        goto set_descriptor_failed;
    }

    ret = get_gdt_descriptor_base(&(*state)->gdtr, (*state)->ldtr_selector, &(*state)->ldtr_base);
    if (ret) {
        bferror("get_gdt_descriptor_base failed");
        goto set_descriptor_failed;
    }

    (*state)->tr_selector = intrinsic_str();

    ret = get_gdt_descriptor_attrib(&(*state)->gdtr, (*state)->tr_selector, &(*state)->tr_attrib);
    if (ret) {
        bferror("get_gdt_descriptor_attrib failed");
        goto set_descriptor_failed;
    }

    ret = get_gdt_descriptor_limit(&(*state)->gdtr, (*state)->tr_selector, &(*state)->tr_limit);
    if (ret) {
        bferror("get_gdt_descriptor_limit failed");
        goto set_descriptor_failed;
    }

    ret = get_gdt_descriptor_base(&(*state)->gdtr, (*state)->tr_selector, &(*state)->tr_base);
    if (ret) {
        bferror("get_gdt_descriptor_base failed");
        goto set_descriptor_failed;
    }

    /**************************************************************************/
    /* Handlers                                                               */
    /**************************************************************************/

    (*state)->promote_handler = &promote;
    (*state)->esr_default_handler = &esr_default;
    (*state)->esr_df_handler = &esr_df;
    (*state)->esr_gpf_handler = &esr_gpf;
    (*state)->esr_nmi_handler = &esr_nmi;
    (*state)->esr_pf_handler = &esr_pf;

    return LOADER_SUCCESS;

set_descriptor_failed:

    platform_free(*state, HYPERVISOR_PAGE_SIZE);
platform_alloc_state_failed:

    *state = ((void *)0);
    return LOADER_FAILURE;
}

#ifdef _MSC_VER
#pragma warning(default : 4152)
#endif
