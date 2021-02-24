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

#include <asm/io.h>
#include <debug.h>
#include <linux/cpu.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/vmalloc.h>
#include <platform.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief This function allocates read/write virtual memory from the
 *     kernel. This memory is not physically contiguous. The resulting
 *     pointer is at least 4k aligned, so use this function sparingly
 *     as it will always allocate at least one page. Use platform_free()
 *     to release this memory.
 *
 *   @note This function must zero the allocated memory
 *
 * <!-- inputs/outputs -->
 *   @param size the number of bytes to allocate
 *   @return Returns a pointer to the newly allocated memory on success.
 *     Returns a nullptr on failure.
 */
void *
platform_alloc(uint64_t const size)
{
    void *ret;

    if (0 == size) {
        bferror("invalid number of bytes (i.e., size)");
        return ((void *)0);
    }

    ret = vmalloc(size);
    if (((void *)0) == ret) {
        bferror("vmalloc failed");
        return ((void *)0);
    }

    return memset(ret, 0, size);
}

/**
 * <!-- description -->
 *   @brief This function allocates read/write virtual memory from the
 *     kernel. This memory is physically contiguous. The resulting
 *     pointer is at least 4k aligned, so use this function sparingly
 *     as it will always allocate at least one page. Use
 *     platform_free_contiguous() to release this memory.
 *
 *   @note This function must zero the allocated memory
 *
 * <!-- inputs/outputs -->
 *   @param size the number of bytes to allocate
 *   @return Returns a pointer to the newly allocated memory on success.
 *     Returns a nullptr on failure.
 */
void *
platform_alloc_contiguous(uint64_t const size)
{
    void *ret;

    if (0 == size) {
        bferror("invalid number of bytes (i.e., size)");
        return ((void *)0);
    }

    ret = kmalloc(size, GFP_KERNEL);
    if (((void *)0) == ret) {
        bferror("kmalloc failed");
        return ((void *)0);
    }

    return memset(ret, 0, size);
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
platform_free(void const *const ptr, uint64_t const size)
{
    (void)size;

    if (((void *)0) != ptr) {
        vfree(ptr);
    }
}

/**
 * <!-- description -->
 *   @brief This function frees memory previously allocated using the
 *     platform_alloc_contiguous() function.
 *
 * <!-- inputs/outputs -->
 *   @param ptr the pointer returned by platform_alloc_contiguous(). If ptr is
 *     passed a nullptr, it will be ignored. Attempting to free memory
 *     more than once results in UB.
 *   @param size the number of bytes that were allocated. Note that this
 *     may or may not be ignored depending on the platform.
 */
void
platform_free_contiguous(void const *const ptr, uint64_t const size)
{
    (void)size;

    if (((void *)0) != ptr) {
        kfree(ptr);
    }
}

/**
 * <!-- description -->
 *   @brief Given a virtual address, this function returns the virtual
 *     address's physical address. Returns ((void *)0) if the conversion failed.
 *
 * <!-- inputs/outputs -->
 *   @param virt the virtual address to convert to a physical address
 *   @return Given a virtual address, this function returns the virtual
 *     address's physical address. Returns ((void *)0) if the conversion failed.
 */
uintptr_t
platform_virt_to_phys(void const *const virt)
{
    uintptr_t ret;

    if (is_vmalloc_addr(virt)) {
        ret = page_to_phys(vmalloc_to_page(virt));
    }
    else {
        ret = virt_to_phys((void *)virt);
    }

    return ret;
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
platform_memset(void *const ptr, uint8_t const val, uint64_t const num)
{
    if (!ptr) {
        bferror("invalid ptr");
        return LOADER_FAILURE;
    }

    memset(ptr, val, num);
    return 0;
}

/**
 * <!-- description -->
 *   @brief Copies "num" bytes from "src" to "dst". If "src" or "dst" are
 *     ((void *)0), returns LOADER_FAILURE, otherwise returns 0.
 *
 * <!-- inputs/outputs -->
 *   @param dst a pointer to the memory to copy to
 *   @param src a pointer to the memory to copy from
 *   @param num the number of bytes to copy
 *   @return If "src" or "dst" are ((void *)0), returns LOADER_FAILURE, otherwise
 *     returns 0.
 */
int64_t
platform_memcpy(void *const dst, void const *const src, uint64_t const num)
{
    if (((void *)0) == dst) {
        bferror("invalid pointer");
        return LOADER_FAILURE;
    }

    if (((void *)0) == src) {
        bferror("invalid pointer");
        return LOADER_FAILURE;
    }

    memcpy(dst, src, num);
    return 0;
}

/**
 * <!-- description -->
 *   @brief Copies "num" bytes from "src" to "dst". If "src" or "dst" are
 *     ((void *)0), returns FAILURE, otherwise returns 0. Note that this function can
 *     be used to copy memory from userspace via an IOCTL.
 *
 * <!-- inputs/outputs -->
 *   @param dst a pointer to the memory to copy to
 *   @param src a pointer to the memory to copy from
 *   @param num the number of bytes to copy
 *   @return If "src" or "dst" are ((void *)0), returns FAILURE, otherwise
 *     returns 0.
 */
int64_t
platform_copy_from_user(
    void *const dst, void const *const src, uint64_t const num)
{
    if (((void *)0) == dst) {
        bferror("invalid pointer");
        return LOADER_FAILURE;
    }

    if (((void *)0) == src) {
        bferror("invalid pointer");
        return LOADER_FAILURE;
    }

    copy_from_user(dst, src, num);
    return 0;
}

/**
 * <!-- description -->
 *   @brief Copies "num" bytes from "src" to "dst". If "src" or "dst" are
 *     ((void *)0), returns FAILURE, otherwise returns 0. Note that this function can
 *     be used to copy memory to userspace via an IOCTL.
 *
 * <!-- inputs/outputs -->
 *   @param dst a pointer to the memory to copy to
 *   @param src a pointer to the memory to copy from
 *   @param num the number of bytes to copy
 *   @return If "src" or "dst" are ((void *)0), returns FAILURE, otherwise
 *     returns 0.
 */
int64_t
platform_copy_to_user(
    void *const dst, void const *const src, uint64_t const num)
{
    if (((void *)0) == dst) {
        bferror("invalid pointer");
        return LOADER_FAILURE;
    }

    if (((void *)0) == src) {
        bferror("invalid pointer");
        return LOADER_FAILURE;
    }

    copy_to_user(dst, src, num);
    return 0;
}

/**
 * <!-- description -->
 *   @brief Returns the total number of online CPUs (i.e. PPs)
 *
 * <!-- inputs/outputs -->
 *   @return Returns the total number of online CPUs (i.e. PPs)
 */
uint32_t
platform_num_online_cpus(void)
{
    return num_online_cpus();
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
    int64_t ret;

    ret = ((platform_per_cpu_func)arg)((uint32_t)smp_processor_id());
    return (long)ret;
}

/**
 * <!-- description -->
 *   @brief Calls the user provided callback on each CPU in forward order.
 *     If each callback returns 0, this function returns 0, otherwise this
 *     function returns a non-0 value, even if all callbacks succeed except
 *     for one. If an error occurs, it is possible that this function will
 *     continue to execute the remaining callbacks until all callbacks have
 *     been called (depends on the platform).
 *
 * <!-- inputs/outputs -->
 *   @param func the function to call on each cpu
 *   @return If each callback returns 0, this function returns 0, otherwise
 *     this function returns a non-0 value
 */
static int64_t
platform_on_each_cpu_forward(platform_per_cpu_func const func)
{
    int64_t ret = 0;
    uint32_t cpu;

    get_online_cpus();
    for (cpu = 0; cpu < num_online_cpus(); ++cpu) {
        if (work_on_cpu(cpu, platform_on_each_cpu_callback, func)) {
            bferror("platform_per_cpu_func failed");
            ret = LOADER_FAILURE;
            break;
        }
    }
    put_online_cpus();

    return ret;
}

/**
 * <!-- description -->
 *   @brief Calls the user provided callback on each CPU in reverse order.
 *     If each callback returns 0, this function returns 0, otherwise this
 *     function returns a non-0 value, even if all callbacks succeed except
 *     for one. If an error occurs, it is possible that this function will
 *     continue to execute the remaining callbacks until all callbacks have
 *     been called (depends on the platform).
 *
 * <!-- inputs/outputs -->
 *   @param func the function to call on each cpu
 *   @return If each callback returns 0, this function returns 0, otherwise
 *     this function returns a non-0 value
 */
static int64_t
platform_on_each_cpu_reverse(platform_per_cpu_func const func)
{
    int64_t ret = 0;
    uint32_t cpu;

    get_online_cpus();
    for (cpu = num_online_cpus(); cpu > 0U; --cpu) {
        if (work_on_cpu(cpu - 1U, platform_on_each_cpu_callback, func)) {
            bferror("platform_per_cpu_func failed");
            ret = LOADER_FAILURE;
            break;
        }
    }
    put_online_cpus();

    return ret;
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
 *   @param order sets the order the CPUs are called
 *   @return If each callback returns 0, this function returns 0, otherwise
 *     this function returns a non-0 value
 */
int64_t
platform_on_each_cpu(platform_per_cpu_func const func, uint32_t const order)
{
    int64_t ret;

    if (PLATFORM_FORWARD == order) {
        ret = platform_on_each_cpu_forward(func);
    }
    else {
        ret = platform_on_each_cpu_reverse(func);
    }

    return ret;
}
