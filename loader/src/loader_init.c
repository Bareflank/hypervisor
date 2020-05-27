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
#include <loader_debug.h>
#include <loader_global_resources.h>
#include <loader_platform.h>
#include <loader_types.h>
#include <loader.h>

/**
 * <!-- description -->
 *   @brief This function contains all of the code that is common between
 *     all archiectures and all platforms that is needed for initializing
 *     the loader. This function will call platform and architecture specific
 *     functions as needed.
 *
 * <!-- inputs/outputs -->
 *   @return Returns 0 on success
 */
int64_t
loader_init(void)
{
    if (platform_memset(&g_contexts, 0, sizeof(g_contexts))) {
        BFERROR("platform_memset failed\n");
        return LOADER_FAILURE;
    }

    if (platform_memset(&g_arch_contexts, 0, sizeof(g_arch_contexts))) {
        BFERROR("platform_memset failed\n");
        return LOADER_FAILURE;
    }

    if (arch_loader_init()) {
        BFERROR("arch_loader_init failed\n");
        return LOADER_FAILURE;
    }

    return 0;
}
