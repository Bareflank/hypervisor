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
#include <platform.h>
#include <stop_and_free_the_vmm.h>
#include <stop_vmm_args_t.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief Verifies that the arguments from the IOCTL are valid.
 *
 * <!-- inputs/outputs -->
 *   @param args the arguments to verify
 *   @return LOADER_SUCCESS on success, LOADER_FAILURE on failure.
 */
static int64_t
verify_stop_vmm_args(struct stop_vmm_args_t const *const args)
{
    if (((uint64_t)1) != args->ver) {
        bferror("IOCTL ABI version not supported");
        return LOADER_FAILURE;
    }

    return LOADER_SUCCESS;
}

/**
 * <!-- description -->
 *   @brief This function contains all of the code that is common between
 *     all archiectures and all platforms for stopping the VMM. This function
 *     will call platform and architecture specific functions as needed.
 *
 * <!-- inputs/outputs -->
 *   @param args arguments from the ioctl
 *   @return LOADER_SUCCESS on success, LOADER_FAILURE on failure.
 */
int64_t
stop_vmm(struct stop_vmm_args_t const *const args)
{
    if (((void *)0) == args) {
        bferror("args was NULL");
        return LOADER_FAILURE;
    }

    if (verify_stop_vmm_args(args)) {
        bferror("verify_stop_vmm_args failed");
        return LOADER_FAILURE;
    }

    stop_and_free_the_vmm();
    return LOADER_SUCCESS;
}
