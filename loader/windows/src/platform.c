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

// clang-format off

/// NOTE:
/// - The windows includes that we use here need to remain in this order.
///   Otherwise the code will not compile.
///

#include <Ntddk.h>

#include <debug.h>
#include <platform.h>
#include <types.h>

// clang-format on

#define BF_TAG 'BFLK'

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
        BFERROR("invalid number of bytes (i.e., size)\n");
        return ((void *)0);
    }

    ret = ExAllocatePoolWithTag(NonPagedPool, size, BF_TAG);
    if (((void *)0) == ret) {
        BFERROR("vmalloc failed\n");
        return ((void *)0);
    }

    RtlFillMemory(ret, size, 0);
    return ret;
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
        BFERROR("invalid number of bytes (i.e., size)\n");
        return ((void *)0);
    }

    PHYSICAL_ADDRESS addr;
    addr.QuadPart = MAXULONG64;

    ret = MmAllocateContiguousMemory(size, addr);
    if (((void *)0) == ret) {
        BFERROR("kmalloc failed\n");
        return ((void *)0);
    }

    RtlFillMemory(ret, size, 0);
    return ret;
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
        ExFreePoolWithTag((void *)ptr, BF_TAG);
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
        MmFreeContiguousMemory((void *)ptr);
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
    PHYSICAL_ADDRESS addr = MmGetPhysicalAddress((PVOID)virt);
    return addr.QuadPart;
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
        BFERROR("invalid ptr\n");
        return LOADER_FAILURE;
    }

    RtlFillMemory(ptr, num, val);
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
        BFERROR("invalid pointer\n");
        return LOADER_FAILURE;
    }

    if (((void *)0) == src) {
        BFERROR("invalid pointer\n");
        return LOADER_FAILURE;
    }

    RtlCopyMemory(dst, src, num);
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
        BFERROR("invalid pointer\n");
        return LOADER_FAILURE;
    }

    if (((void *)0) == src) {
        BFERROR("invalid pointer\n");
        return LOADER_FAILURE;
    }

    RtlCopyMemory(dst, src, num);
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
        BFERROR("invalid pointer\n");
        return LOADER_FAILURE;
    }

    if (((void *)0) == src) {
        BFERROR("invalid pointer\n");
        return LOADER_FAILURE;
    }

    RtlCopyMemory(dst, src, num);
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
    return KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
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
    (void)func;
    int64_t ret = 0;

    ULONG Count;
    ULONG ProcIndex;
    PROCESSOR_NUMBER ProcNumber;

    Count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    for (ProcIndex = 0; ProcIndex < Count; ++ProcIndex) {
        GROUP_AFFINITY affinity = {0};
        GROUP_AFFINITY previous = {0};

        KeGetProcessorNumberFromIndex(ProcIndex, &ProcNumber);

        affinity.Mask = (1ULL << ProcNumber.Number);
        affinity.Group = ProcNumber.Group;

        KeSetSystemGroupAffinityThread(&affinity, &previous);
        ret = func(ProcIndex);
        KeRevertToUserGroupAffinityThread(&previous);

        if (ret) {
            BFERROR("platform_per_cpu_func failed\n");
            return ret;
        }
    }

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

    ULONG Count;
    ULONG ProcIndex;
    PROCESSOR_NUMBER ProcNumber;

    Count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    for (ProcIndex = Count; ProcIndex > 0; --ProcIndex) {
        GROUP_AFFINITY affinity = {0};
        GROUP_AFFINITY previous = {0};

        KeGetProcessorNumberFromIndex(ProcIndex - 1, &ProcNumber);

        affinity.Mask = (1ULL << ProcNumber.Number);
        affinity.Group = ProcNumber.Group;

        KeSetSystemGroupAffinityThread(&affinity, &previous);
        ret = func(ProcIndex - 1);
        KeRevertToUserGroupAffinityThread(&previous);

        if (ret) {
            BFERROR("platform_per_cpu_func failed\n");
            return ret;
        }
    }

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
