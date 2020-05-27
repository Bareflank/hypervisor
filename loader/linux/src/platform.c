/* SPDX-License-Identifier: SPDX-License-Identifier: GPL-2.0 OR MIT */

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
#include <loader.h>

#include <asm/io.h>
#include <linux/cpu.h>
#include <linux/mm.h>
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
platform_alloc(uintmax_t const size)
{
    void *ptr = NULL;

    if (0 == size) {
        BFALERT("invalid number of bytes (i.e., size)\n");
        return ptr;
    }

    ptr = vmalloc(size);
    if (NULL == ptr) {
        BFALERT("vmalloc failed\n");
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
platform_free(void *const ptr, uintmax_t const size)
{
    if (NULL == ptr) {
        return;
    }

    vfree(ptr);
}

/**
 * <!-- description -->
 *   @brief Given a virtual address, this function returns the virtual
 *     address's physical address. Returns NULL if the conversion failed.
 *
 * <!-- inputs/outputs -->
 *   @param virt the virtual address to convert to a physical address
 *   @return Given a virtual address, this function returns the virtual
 *     address's physical address. Returns NULL if the conversion failed.
 */
uintptr_t
platform_virt_to_phys(void const *const virt)
{
    if (is_vmalloc_addr(virt)) {
        return page_to_phys(vmalloc_to_page(virt));
    }
    else {
        return virt_to_phys((void *)virt);
    }
}

/**
 * <!-- description -->
 *   @brief Sets "num" bytes in the memory pointed to by "ptr" to "val".
 *     If the provided parameters are valid, returns 0, otherwise
 *     returns LOADER_FAILURE.
 *
 * <!-- inputs/outputs -->
 *   @param ptr a pointer to the memory to set
 *   @param val the value to set each byte to
 *   @param num the number of bytes in "ptr" to set to "val".
 *   @return If the provided parameters are valid, returns 0, otherwise
 *     returns LOADER_FAILURE.
 */
int64_t
platform_memset(void *const ptr, uint8_t const val, uintmax_t const num)
{
    if (!ptr) {
        BFALERT("invalid ptr\n");
        return LOADER_FAILURE;
    }

    memset(ptr, val, num);
    return 0;
}

/**
 * <!-- description -->
 *   @brief Copies "num" bytes from "src" to "dst". If "src" or "dst" are
 *     NULL, returns LOADER_FAILURE, otherwise returns 0.
 *
 * <!-- inputs/outputs -->
 *   @param dst a pointer to the memory to copy to
 *   @param src a pointer to the memory to copy from
 *   @param num the number of bytes to copy
 *   @return If "src" or "dst" are NULL, returns LOADER_FAILURE, otherwise
 *     returns 0.
 */
int64_t
platform_memcpy(void *const dst, void const *const src, uintmax_t const num)
{
    if (dst == 0 || src == 0) {
        BFALERT("invalid dst/src pointers\n");
        return LOADER_FAILURE;
    }

    memcpy(dst, src, num);
    return 0;
}

/**
 * <!-- description -->
 *   @brief This function is called when the user calls platform_on_each_cpu.
 *     On each iteration of the CPU, this function calls the user provided
 *     callback with the signature that we perfer, providing us with a way
 *     to be compatable with Linux.
 *
 * <!-- inputs/outputs -->
 *   @param dummy ignored
 */
static long
platform_on_each_cpu_callback(void *const arg)
{
    platform_per_cpu_func func = (platform_per_cpu_func)arg;
    if (func((uint32_t)smp_processor_id())) {
        return LOADER_FAILURE;
    }

    return 0;
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
 *   @param reverse if set to 1, will execute the func in reverse order
 *   @return If each callback returns 0, this function returns 0, otherwise
 *     this function returns a non-0 value
 */
int64_t
platform_on_each_cpu(platform_per_cpu_func const func, uint32_t const reverse)
{
    uint32_t cpu;
    get_online_cpus();

    if (reverse == 0) {
        for (cpu = 0; cpu < num_online_cpus(); ++cpu) {
            if (work_on_cpu(cpu, platform_on_each_cpu_callback, func)) {
                BFERROR("platform_per_cpu_func failed\n");
                put_online_cpus();
                return LOADER_FAILURE;
            }
        }
    }
    else {
        for (cpu = num_online_cpus() - 1; cpu >= 0; --cpu) {
            if (work_on_cpu(cpu, platform_on_each_cpu_callback, func)) {
                BFERROR("platform_per_cpu_func failed\n");
                put_online_cpus();
                return LOADER_FAILURE;
            }
        }
    }

    put_online_cpus();
    return 0;
}
