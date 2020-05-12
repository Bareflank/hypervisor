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

#include <loader_debug.h>
#include <loader_platform.h>
#include <loader_types.h>

#include <linux/smp.h>
#include <linux/vmalloc.h>

/**
 * <!-- description -->
 *   @brief This function allocates read/write virtual memory from the
 *     kernel. This memory is not physically contiguous. The resulting
 *     pointer is at least 4k aligned, so use this function sparingly
 *     as it will always allocate at least one page. Use platform_free()
 *     to release this memory.
 *
 * <!-- inputs/outputs -->
 *   @param size the number of bytes to allocate
 *   @return Returns a pointer to the newly allocated memory on success.
 *     Returns a nullptr on failure.
 */
void *
platform_alloc(uint64_t size)
{
    void *ptr = NULL;

    if (0 == size) {
        BFALERT("platform_alloc: invalid number of bytes (i.e., size)\n");
        return ptr;
    }

    ptr = vmalloc(size);
    if (NULL == ptr) {
        BFALERT("platform_alloc: vmalloc failed\n");
    }

    return ptr;
}

/**
 * <!-- description -->
 *   @brief This function frees memory previously allocated using the
 *     platform_alloc() function.
 *
 * <!-- inputs/outputs -->
 *   @param ptr the pointer returned by platform_alloc(). If ptr is
 *     passed a nullptr, it will be ignored. Attempting to free memory
 *     more than once results in UB.
 *   @param size the number of bytes that were allocated. Note that this
 *     may or may not be ignored depending on the platform.
 */
void
platform_free(void *ptr, uint64_t size)
{
    if (NULL == ptr) {
        return;
    }

    vfree(ptr);
}

/**
 * @struct on_cpu_info
 *
 * <!-- description -->
 *   @brief Since the on_each_cpu function does not provide a return type
 *     we use this structure to add a return type. We then call an internal
 *     function that converts the callback function signature that we want
 *     to the Linux callback signature.
 */
struct on_cpu_info
{
    platform_per_cpu_func func;
    int64_t ret;
};

/**
 * <!-- description -->
 *   @brief This function is called when the user calls platform_on_each_cpu.
 *     On each iteration of the CPU, this function calls the user provided
 *     callback with the signature that we perfer, providing us with a way
 *     to be compatable with Linux.
 *
 * <!-- inputs/outputs -->
 *   @param info a pointer to a on_cpu_info structure
 */
static void
platform_on_each_cpu_callback(void *info)
{
    struct on_cpu_info *_info = (struct on_cpu_info *)info;

    if (_info->func((uint64_t)smp_processor_id()) != 0) {
        _info->ret = FAILURE;
    }
}

/**
 * <!-- description -->
 *   @brief Calls the user provided callback on each CPU. If each callback
 *     returns 0, this function returns 0, otherwise this function returns
 *     a non-0 value, even if all callbacks succeed except for one. If an
 *     error occurs, it is possible that this function will continue to
 *     execute the remaining callbacks until all callbacks have been called
 *     (depends on the platform).
 *
 * <!-- inputs/outputs -->
 *   @param func the function to call on each cpu
 *   @return If each callback returns 0, this function returns 0, otherwise
 *     this function returns a non-0 value
 */
int64_t
platform_on_each_cpu(platform_per_cpu_func func)
{
    struct on_cpu_info info = {func, 0};
    on_each_cpu(&platform_on_each_cpu_callback, &info, 1);

    return info.ret;
}
