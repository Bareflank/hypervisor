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
#include <exception_vectors.h>
#include <platform.h>
#include <promote.h>
#include <read_daif.h>
#include <read_hcr_el2.h>
#include <read_mair_el2.h>
#include <read_sctlr_el2.h>
#include <read_spsel.h>
#include <read_tcr_el2.h>
#include <read_ttbr0_el2.h>
#include <read_vbar_el2.h>
#include <state_save_t.h>
#include <types.h>

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
NODISCARD int64_t
alloc_and_copy_root_vp_state(struct state_save_t **const state) NOEXCEPT
{
    *state = (struct state_save_t *)platform_alloc(HYPERVISOR_PAGE_SIZE);
    if (NULLPTR == *state) {
        bferror("platform_alloc failed");
        return LOADER_FAILURE;
    }

    /**************************************************************************/
    /* Saved Program Status Registers (SPSR)                                  */
    /**************************************************************************/

    (*state)->daif = read_daif();
    (*state)->spsel = read_spsel();

    /**************************************************************************/
    /* Exceptions                                                             */
    /**************************************************************************/

    (*state)->vbar_el2 = read_vbar_el2();

    /**************************************************************************/
    /* System Registers                                                       */
    /**************************************************************************/

    (*state)->hcr_el2 = read_hcr_el2();
    (*state)->mair_el2 = read_mair_el2();
    (*state)->sctlr_el2 = read_sctlr_el2();
    (*state)->tcr_el2 = read_tcr_el2();
    (*state)->ttbr0_el2 = read_ttbr0_el2();

    /**************************************************************************/
    /* Handlers                                                               */
    /**************************************************************************/

    (*state)->promote_handler = &promote;
    (*state)->exception_vectors = &exception_vectors;

    return LOADER_SUCCESS;
}
