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

#ifndef PLATFORM_H
#define PLATFORM_H

#include <types.h>

#ifdef __cplusplus
extern "C"
{
#endif

/** @brief execute each CPU in forward order (i.e., incrementing) */
#define PLATFORM_FORWARD ((uint32_t)0U)
/** @brief execute each CPU in reverse order (i.e., decrementing) */
#define PLATFORM_REVERSE ((uint32_t)1U)

    /**
    * @brief The callback signature for platform_on_each_cpu
    */
    typedef int64_t (*platform_per_cpu_func)(uint32_t const);

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
    void platform_expects(int const test) NOEXCEPT;

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
    void platform_ensures(int const test) NOEXCEPT;

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
    NODISCARD void *platform_alloc(uint64_t const size) NOEXCEPT;

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
    NODISCARD void *platform_alloc_contiguous(uint64_t const size) NOEXCEPT;

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
    void platform_free(void const *const ptr, uint64_t const size) NOEXCEPT;

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
    void platform_free_contiguous(void const *const ptr, uint64_t const size) NOEXCEPT;

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
    NODISCARD uintptr_t platform_virt_to_phys(void const *const virt) NOEXCEPT;

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
    void platform_memset(void *const pmut_ptr, uint8_t const val, uint64_t const num) NOEXCEPT;

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
    void platform_memcpy(void *const pmut_dst, void const *const src, uint64_t const num) NOEXCEPT;

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
    NODISCARD int64_t platform_copy_from_user(
        void *const pmut_dst, void const *const src, uint64_t const num) NOEXCEPT;

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
    platform_copy_to_user(void *const pmut_dst, void const *const src, uint64_t const num) NOEXCEPT;

    /**
     * <!-- description -->
     *   @brief Returns the total number of online CPUs (i.e. PPs)
     *
     * <!-- inputs/outputs -->
     *   @return Returns the total number of online CPUs (i.e. PPs)
     */
    NODISCARD uint32_t platform_num_online_cpus(void) NOEXCEPT;

    /**
     * <!-- description -->
     *   @brief Returns the current CPU (i.e. PP)
     *
     * <!-- inputs/outputs -->
     *   @return Returns the current CPU (i.e. PP)
     */
    NODISCARD uint32_t platform_current_cpu(void) NOEXCEPT;

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
    platform_on_each_cpu(platform_per_cpu_func const pmut_func, uint32_t const order) NOEXCEPT;

    /**
     * <!-- description -->
     *   @brief Dumps the contents of the VMM's ring buffer.
     */
    void platform_dump_vmm(void) NOEXCEPT;

    /**
     * <!-- description -->
     *   @brief Initializes the architecture. Some platforms might need per CPU
     *     initialization logic to get the CPU set up. Most platforms ignore
     *     calls to this function
     *
     * <!-- inputs/outputs -->
     *   @return Returns 0 on success, LOADER_FAILURE otherwise
     */
    NODISCARD int64_t platform_arch_init(void) NOEXCEPT;

    /**
     * <!-- description -->
     *   @brief Marks the current GDT as read/write
     */
    void platform_mark_gdt_writable(void) NOEXCEPT;

    /**
     * <!-- description -->
     *   @brief Marks the current GDT as read-only
     */
    void platform_mark_gdt_readonly(void) NOEXCEPT;

#ifdef __cplusplus
}
#endif

#endif
