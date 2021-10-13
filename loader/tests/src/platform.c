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

#include <assert.h>
#include <debug.h>
#include <platform.h>
#include <stdlib.h>
#include <string.h>
#include <types.h>

int32_t g_mut_platform_alloc = 0;
int32_t g_mut_platform_alloc_contiguous = 0;
int32_t g_mut_platform_virt_to_phys = 0;
int32_t g_mut_platform_copy_from_user = 0;
int32_t g_mut_platform_copy_to_user = 0;
int32_t g_mut_platform_arch_init = 0;

/**
 * <!-- description -->
 *   @brief Returns true if the provided address is page aligned,
 *     returns false otherwise.
 *
 * <!-- inputs/outputs -->
 *   @param addr the address to query
 *   @return Returns 0 if the provided address is page aligned,
 *     returns a non-zero value otherwise.
 */
NODISCARD static inline int
bf_is_page_aligned(uint64_t const addr) NOEXCEPT
{
    uint64_t const mask = HYPERVISOR_PAGE_SIZE - ((uint64_t)1);
    return ((uint64_t)0) == (addr & mask);
}

/**
 * <!-- description -->
 *   @brief Returns the page aligned version of the addr
 *
 * <!-- inputs/outputs -->
 *   @param addr the address to query
 *   @return Returns the page aligned version of the addr
 */
NODISCARD static inline uint64_t
bf_page_aligned(uint64_t const addr) NOEXCEPT
{
    uint64_t const one = ((uint64_t)1);
    return (addr & ~(HYPERVISOR_PAGE_SIZE - one));
}

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
    if (0 == test) {                              // GRCOV_EXCLUDE_BR
        bferror("expects contract violation");    // GRCOV_EXCLUDE
        assert(0);                                // GRCOV_EXCLUDE // NOLINT
    }                                             // GRCOV_EXCLUDE
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
    if (0 == test) {                              // GRCOV_EXCLUDE_BR
        bferror("expects contract violation");    // GRCOV_EXCLUDE
        assert(0);                                // GRCOV_EXCLUDE // NOLINT
    }                                             // GRCOV_EXCLUDE
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
    uint64_t mut_size = size;
    if (!bf_is_page_aligned(size)) {
        mut_size = bf_page_aligned(size + HYPERVISOR_PAGE_SIZE);
    }

    if (g_mut_platform_alloc > 0) {
        --g_mut_platform_alloc;

        if (0 == g_mut_platform_alloc) {
            return NULLPTR;
        }

        bf_touch();
    }
    else {
        bf_touch();
    }

#ifdef _WIN32
    return memset(_aligned_malloc(mut_size, HYPERVISOR_PAGE_SIZE), 0, mut_size);    // NOLINT
#else
    return memset(aligned_alloc(HYPERVISOR_PAGE_SIZE, mut_size), 0, mut_size);    // NOLINT
#endif
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
    uint64_t mut_size = size;
    if (!bf_is_page_aligned(size)) {
        mut_size = bf_page_aligned(size + HYPERVISOR_PAGE_SIZE);
    }

    if (g_mut_platform_alloc_contiguous > 0) {
        --g_mut_platform_alloc_contiguous;

        if (0 == g_mut_platform_alloc_contiguous) {
            return NULLPTR;
        }

        bf_touch();
    }
    else {
        bf_touch();
    }

#ifdef _WIN32
    return memset(_aligned_malloc(mut_size, HYPERVISOR_PAGE_SIZE), 0, mut_size);    // NOLINT
#else
    return memset(aligned_alloc(HYPERVISOR_PAGE_SIZE, mut_size), 0, mut_size);    // NOLINT
#endif
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
#ifdef _WIN32
    _aligned_free((void *)ptr);
#else
    free((void *)ptr);                                                            // NOLINT
#endif
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
#ifdef _WIN32
    _aligned_free((void *)ptr);
#else
    free((void *)ptr);                                                            // NOLINT
#endif
}

/**
 * <!-- description -->
 *   @brief Given a virtual address, this function returns the virtual
 *     address's physical address. Only works with memory allocated using
 *     platform_alloc. Returns NULLPTR if the conversion failed.
 *
 * <!-- inputs/outputs -->
 *   @param virt the virtual address to convert to a physical address
 *   @return Given a virtual address, this function returns the virtual
 *     address's physical address. Only works with memory allocated using
 *     platform_alloc. Returns NULLPTR if the conversion failed.
 */
NODISCARD uintptr_t
platform_virt_to_phys(void const *const virt) NOEXCEPT
{
    if (g_mut_platform_virt_to_phys > 0) {
        --g_mut_platform_virt_to_phys;

        if (0 == g_mut_platform_virt_to_phys) {
            return ((uintptr_t)0);
        }

        bf_touch();
    }
    else {
        bf_touch();
    }

    return (uintptr_t)virt;
}

/**
 * <!-- description -->
 *   @brief Sets "num" bytes in the memory pointed to by "ptr" to "val".
 *     If the provided parameters are valid, returns 0, otherwise
 *     returns SHIM_FAILURE.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_ptr a pointer to the memory to set
 *   @param val the value to set each byte to
 *   @param num the number of bytes in "pmut_ptr" to set to "val".
 */
void
platform_memset(void *const pmut_ptr, uint8_t const val, uint64_t const num) NOEXCEPT
{
    platform_expects(NULLPTR != pmut_ptr);
    memset(pmut_ptr, val, num);    // NOLINT
}

/**
 * <!-- description -->
 *   @brief Copies "num" bytes from "src" to "pmut_dst". If "src" or "pmut_dst" are
 *     NULLPTR, returns SHIM_FAILURE, otherwise returns 0.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_dst a pointer to the memory to copy to
 *   @param src a pointer to the memory to copy from
 *   @param num the number of bytes to copy
 */
void
platform_memcpy(void *const pmut_dst, void const *const src, uint64_t const num) NOEXCEPT
{
    platform_expects(NULLPTR != pmut_dst);
    platform_expects(NULLPTR != src);

    memcpy(pmut_dst, src, num);    // NOLINT
}

/**
 * <!-- description -->
 *   @brief Copies "num" bytes from "src" to "pmut_dst". Returns
 *     SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_dst a pointer to the memory to copy to
 *   @param src a pointer to the memory to copy from
 *   @param num the number of bytes to copy
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
platform_copy_from_user(void *const pmut_dst, void const *const src, uint64_t const num) NOEXCEPT
{
    platform_expects(NULLPTR != pmut_dst);
    platform_expects(NULLPTR != src);

    if (g_mut_platform_copy_from_user > 0) {
        --g_mut_platform_copy_from_user;
        return LOADER_FAILURE;
    }

    memcpy(pmut_dst, src, num);    // NOLINT
    return LOADER_SUCCESS;
}

/**
 * <!-- description -->
 *   @brief Copies "num" bytes from "src" to "pmut_dst". Returns
 *     SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_dst a pointer to the memory to copy to
 *   @param src a pointer to the memory to copy from
 *   @param num the number of bytes to copy
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
platform_copy_to_user(void *const pmut_dst, void const *const src, uint64_t const num) NOEXCEPT
{
    platform_expects(NULLPTR != pmut_dst);
    platform_expects(NULLPTR != src);

    if (g_mut_platform_copy_to_user > 0) {
        --g_mut_platform_copy_to_user;
        return LOADER_FAILURE;
    }

    memcpy(pmut_dst, src, num);    // NOLINT
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
    return 1U;
}

/**
 * <!-- description -->
 *   @brief Returns the current CPU (i.e. PP)
 *
 * <!-- inputs/outputs -->
 *   @return Returns the current CPU (i.e. PP)
 */
NODISCARD uint32_t
platform_current_cpu(void) NOEXCEPT
{
    return 0U;
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
 *   @param pmut_func the function to call on each cpu
 *   @param order sets the order the CPUs are called
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
platform_on_each_cpu(platform_per_cpu_func const pmut_func, uint32_t const order) NOEXCEPT
{
    (void)order;
    return pmut_func(0U);
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
 *   @brief Initializes the architecture. Some platforms might need per CPU
 *     initialization logic to get the CPU set up. Most platforms ignore
 *     calls to this function
 *
 * <!-- inputs/outputs -->
 *   @return Returns 0 on success, LOADER_FAILURE otherwise
 */
NODISCARD int64_t
platform_arch_init(void) NOEXCEPT
{
    if (g_mut_platform_arch_init > 0) {
        --g_mut_platform_arch_init;
        return LOADER_FAILURE;
    }

    return LOADER_SUCCESS;
}

/**
 * <!-- description -->
 *   @brief Marks the current GDT as read/write
 */
void
platform_mark_gdt_writable(void) NOEXCEPT
{}

/**
 * <!-- description -->
 *   @brief Marks the current GDT as read-only
 */
void
platform_mark_gdt_readonly(void) NOEXCEPT
{}
