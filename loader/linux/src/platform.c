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
#include <work_on_cpu_callback_args.h>

/**
 * <!-- description -->
 *   @brief If test is false, a contract violation has occurred. This
 *     should be used to assert preconditions that if not meet, would
 *     result in undefined behavior. These should not be tested by a
 *     unit test, meaning they are contract violations. These asserts
 *     are simply there as a sanity check during a debug build.
 *
 * <!-- inputs/outputs -->
 *   @param test the contract to check
 */
void
platform_expects(int const test) NOEXCEPT
{
    BUG_ON(!test);
}

/**
 * <!-- description -->
 *   @brief If test is false, a contract violation has occurred. This
 *     should be used to assert postconditions that if not meet, would
 *     result in undefined behavior. These should not be tested by a
 *     unit test, meaning they are contract violations. These asserts
 *     are simply there as a sanity check during a debug build.
 *
 * <!-- inputs/outputs -->
 *   @param test the contract to check
 */
void
platform_ensures(int const test) NOEXCEPT
{
    BUG_ON(!test);
}

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
NODISCARD void *
platform_alloc(uint64_t const size) NOEXCEPT
{
    void *mut_ret;

    if (0 == size) {
        bferror("invalid number of bytes (i.e., size)");
        return NULLPTR;
    }

    mut_ret = vmalloc(size);
    if (NULLPTR == mut_ret) {
        bferror("vmalloc failed");
        return NULLPTR;
    }

    return memset(mut_ret, 0, size);
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
NODISCARD void *
platform_alloc_contiguous(uint64_t const size) NOEXCEPT
{
    void *mut_ret;

    if (0 == size) {
        bferror("invalid number of bytes (i.e., size)");
        return NULLPTR;
    }

    mut_ret = kmalloc(size, GFP_KERNEL);
    if (NULLPTR == mut_ret) {
        bferror("kmalloc failed");
        return NULLPTR;
    }

    return memset(mut_ret, 0, size);
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
platform_free(void const *const ptr, uint64_t const size) NOEXCEPT
{
    (void)size;

    if (NULLPTR != ptr) {
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
platform_free_contiguous(void const *const ptr, uint64_t const size) NOEXCEPT
{
    (void)size;

    if (NULLPTR != ptr) {
        kfree(ptr);
    }
}

/**
 * <!-- description -->
 *   @brief Given a virtual address, this function returns the virtual
 *     address's physical address. Returns NULLPTR if the conversion failed.
 *
 * <!-- inputs/outputs -->
 *   @param virt the virtual address to convert to a physical address
 *   @return Given a virtual address, this function returns the virtual
 *     address's physical address. Returns NULLPTR if the conversion failed.
 */
NODISCARD uintptr_t
platform_virt_to_phys(void const *const virt) NOEXCEPT
{
    uintptr_t mut_ret;

    if (is_vmalloc_addr(virt)) {
        mut_ret = page_to_phys(vmalloc_to_page(virt));
    }
    else {
        mut_ret = virt_to_phys((void *)virt);
    }

    return mut_ret;
}

/**
 * <!-- description -->
 *   @brief Sets "num" bytes in the memory pointed to by "ptr" to "val".
 *     If the provided parameters are valid, returns 0, otherwise
 *     returns LOADER_FAILURE.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_ptr a pointer to the memory to set
 *   @param val the value to set each byte to
 *   @param num the number of bytes in "ptr" to set to "val".
 */
void
platform_memset(
    void *const pmut_ptr, uint8_t const val, uint64_t const num) NOEXCEPT
{
    platform_expects(NULLPTR != pmut_ptr);
    memset(pmut_ptr, val, num);
}

/**
 * <!-- description -->
 *   @brief Copies "num" bytes from "src" to "dst". If "src" or "dst" are
 *     NULLPTR, returns LOADER_FAILURE, otherwise returns 0.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_dst a pointer to the memory to copy to
 *   @param src a pointer to the memory to copy from
 *   @param num the number of bytes to copy
 */
void
platform_memcpy(
    void *const pmut_dst, void const *const src, uint64_t const num) NOEXCEPT
{
    platform_expects(NULLPTR != pmut_dst);
    platform_expects(NULLPTR != src);

    memcpy(pmut_dst, src, num);
}

/**
 * <!-- description -->
 *   @brief Copies "num" bytes from "src" to "dst". If "src" or "dst" are
 *     NULLPTR, returns FAILURE, otherwise returns 0. Note that this function can
 *     be used to copy memory from userspace via an IOCTL.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_dst a pointer to the memory to copy to
 *   @param src a pointer to the memory to copy from
 *   @param num the number of bytes to copy
 *   @return If "src" or "dst" are NULLPTR, returns FAILURE, otherwise
 *     returns 0.
 */
NODISCARD int64_t
platform_copy_from_user(
    void *const pmut_dst, void const *const src, uint64_t const num) NOEXCEPT
{
    platform_expects(NULLPTR != pmut_dst);
    platform_expects(NULLPTR != src);

    if (copy_from_user(pmut_dst, src, num)) {
        return LOADER_FAILURE;
    }

    return LOADER_SUCCESS;
}

/**
 * <!-- description -->
 *   @brief Copies "num" bytes from "src" to "dst". If "src" or "dst" are
 *     NULLPTR, returns FAILURE, otherwise returns 0. Note that this function can
 *     be used to copy memory to userspace via an IOCTL.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_dst a pointer to the memory to copy to
 *   @param src a pointer to the memory to copy from
 *   @param num the number of bytes to copy
 *   @return If "src" or "dst" are NULLPTR, returns FAILURE, otherwise
 *     returns 0.
 */
NODISCARD int64_t
platform_copy_to_user(
    void *const pmut_dst, void const *const src, uint64_t const num) NOEXCEPT
{
    platform_expects(NULLPTR != pmut_dst);
    platform_expects(NULLPTR != src);

    if (copy_to_user(pmut_dst, src, num)) {
        return LOADER_FAILURE;
    }

    return LOADER_SUCCESS;
}

/**
 * <!-- description -->
 *   @brief Returns the total number of online CPUs (i.e. PPs)
 *
 * <!-- inputs/outputs -->
 *   @return Returns the total number of online CPUs (i.e. PPs)
 */
NODISCARD uint32_t
platform_num_online_cpus(void) NOEXCEPT
{
    return num_online_cpus();
}

/**
 * <!-- description -->
 *   @brief This function is called when the user calls platform_on_each_cpu.
 *     On each iteration of the CPU, this function calls the user provided
 *     callback with the signature that we perfer.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_arg stores the params needed to execute the callback
 */
NODISCARD static long
work_on_cpu_callback(void *const pmut_arg) NOEXCEPT
{
    struct work_on_cpu_callback_args *const pmut_args =
        ((struct work_on_cpu_callback_args *)pmut_arg);

    pmut_args->ret = pmut_args->func(pmut_args->cpu);
    return 0;
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
NODISCARD static int64_t
platform_on_each_cpu_forward(platform_per_cpu_func const func) NOEXCEPT
{
    uint32_t mut_cpu;

    get_online_cpus();
    for (mut_cpu = 0; mut_cpu < platform_num_online_cpus(); ++mut_cpu) {
        struct work_on_cpu_callback_args args = {func, mut_cpu, 0, 0};

        work_on_cpu(mut_cpu, work_on_cpu_callback, &args);
        if (args.ret) {
            bferror("platform_per_cpu_func failed");
            goto work_on_cpu_callback_failed;
        }
    }

    put_online_cpus();
    return LOADER_SUCCESS;

work_on_cpu_callback_failed:
    put_online_cpus();
    return LOADER_FAILURE;
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
NODISCARD static int64_t
platform_on_each_cpu_reverse(platform_per_cpu_func const func) NOEXCEPT
{
    uint32_t mut_cpu;

    get_online_cpus();
    for (mut_cpu = platform_num_online_cpus(); mut_cpu > 0; --mut_cpu) {
        struct work_on_cpu_callback_args args = {func, mut_cpu - 1, 0, 0};

        work_on_cpu(mut_cpu - 1U, work_on_cpu_callback, &args);
        if (args.ret) {
            bferror("platform_per_cpu_func failed");
            goto work_on_cpu_callback_failed;
        }
    }

    put_online_cpus();
    return LOADER_SUCCESS;

work_on_cpu_callback_failed:
    put_online_cpus();
    return LOADER_FAILURE;
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
NODISCARD int64_t
platform_on_each_cpu(
    platform_per_cpu_func const func, uint32_t const order) NOEXCEPT
{
    int64_t mut_ret;

    if (PLATFORM_FORWARD == order) {
        mut_ret = platform_on_each_cpu_forward(func);
    }
    else {
        mut_ret = platform_on_each_cpu_reverse(func);
    }

    return mut_ret;
}

/**
 * <!-- description -->
 *   @brief Dumps the contents of the VMM's ring buffer.
 */
void
platform_dump_vmm(void) NOEXCEPT
{}

/**
 * <!-- description -->
 *   @brief Initializes the archiecture. Some platforms might need per CPU
 *     initialization logic to get the CPU set up. Most platforms ignore
 *     calls to this function
 *
 * <!-- inputs/outputs -->
 *   @return Returns 0 on success, LOADER_FAILURE otherwise
 */
NODISCARD int64_t
platform_arch_init(void) NOEXCEPT
{
    return LOADER_SUCCESS;
}

/**
 * <!-- description -->
 *   @brief Marks the current GDT as read/write
 */
void
platform_mark_gdt_writable(void) NOEXCEPT
{
    load_direct_gdt(raw_smp_processor_id());
}

/**
 * <!-- description -->
 *   @brief Marks the current GDT as read-only
 */
void
platform_mark_gdt_readonly(void) NOEXCEPT
{
    load_fixmap_gdt(raw_smp_processor_id());
}
