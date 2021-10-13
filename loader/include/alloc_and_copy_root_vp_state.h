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

#ifndef ALLOC_AND_COPY_ROOT_VP_STATE_H
#define ALLOC_AND_COPY_ROOT_VP_STATE_H

#include <state_save_t.h>
#include <types.h>

#ifdef __cplusplus
extern "C"
{
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
     *   @param pmut_state where to save the newly allocated state to
     *   @return LOADER_SUCCESS on success, LOADER_FAILURE on failure.
     */
    NODISCARD int64_t alloc_and_copy_root_vp_state(struct state_save_t **const pmut_state) NOEXCEPT;

#ifdef __cplusplus
}
#endif

#endif
