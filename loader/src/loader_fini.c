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
#include <free_mk_code_aliases.h>
#include <free_mk_debug_ring.h>
#include <g_mk_code_aliases.h>
#include <g_mk_debug_ring.h>
#include <platform.h>
#include <types.h>
#include <vmm_status.h>

/**
 * <!-- description -->
 *   @brief This function contains all of the code that is common between
 *     all archiectures and all platforms that is needed for finalizing
 *     the loader. This function will call platform and architecture specific
 *     functions as needed.
 *
 * <!-- inputs/outputs -->
 *   @return 0 on success, LOADER_FAILURE on failure.
 */
int64_t
loader_fini(void)
{
    if (VMM_STATUS_CORRUPT == g_vmm_status) {
        bferror("Unable to fini, a VMM failed to properly stop");
        return LOADER_FAILURE;
    }

    free_mk_code_aliases(&g_mk_code_aliases);
    free_mk_debug_ring(&g_mk_debug_ring);

    return LOADER_SUCCESS;
}
