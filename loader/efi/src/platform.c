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

#include <arch_init.h>
#include <arch_num_online_cpus.h>
#include <arch_work_on_cpu.h>
#include <constants.h>
#include <debug.h>
#include <debug_ring_t.h>
#include <efi/efi_status.h>
#include <efi/efi_system_table.h>
#include <efi/efi_types.h>
#include <g_pmut_mut_mk_debug_ring.h>
#include <platform.h>
#include <work_on_cpu_callback.h>

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
    if (0 == test) {
        bferror("expects contract violation");
        (void)g_st->BootServices->Stall(((UINTN)0xFFFFFFFFFFFFFFFF));
    }
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
    if (0 == test) {
        bferror("ensures contract violation");
        (void)g_st->BootServices->Stall(((UINTN)0xFFFFFFFFFFFFFFFF));
    }
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
platform_alloc(uint64_t size)
{
    EFI_STATUS status = EFI_SUCCESS;
    EFI_PHYSICAL_ADDRESS ret = ((EFI_PHYSICAL_ADDRESS)0);

    platform_expects(((uint64_t)0) != size);

    if (((uint64_t)0) != (size & (HYPERVISOR_PAGE_SIZE - ((uint64_t)1)))) {
        size += HYPERVISOR_PAGE_SIZE;
        size &= ~(HYPERVISOR_PAGE_SIZE - ((uint64_t)1));
    }

    status = g_st->BootServices->AllocatePages(
        AllocateAnyPages, EfiRuntimeServicesData, size / HYPERVISOR_PAGE_SIZE, &ret);
    if (EFI_ERROR(status)) {
        bferror_x64("AllocatePages failed", status);
        return NULL;
    }

    g_st->BootServices->SetMem((void *)ret, size, ((UINT8)0));
    return (void *)ret;
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
platform_alloc_contiguous(uint64_t const size)
{
    return platform_alloc(size);
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
platform_free(void const *const ptr, uint64_t size)
{
    platform_expects(NULLPTR != ptr);
    platform_expects(((uint64_t)0) != size);

    if (((uint64_t)0) != (size & (HYPERVISOR_PAGE_SIZE - ((uint64_t)1)))) {
        size += HYPERVISOR_PAGE_SIZE;
        size &= ~(HYPERVISOR_PAGE_SIZE - ((uint64_t)1));
    }

    g_st->BootServices->FreePages((EFI_PHYSICAL_ADDRESS)ptr, size / HYPERVISOR_PAGE_SIZE);
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
    platform_free(ptr, size);
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
NODISCARD uintptr_t
platform_virt_to_phys(void const *const virt)
{
    platform_expects(NULLPTR != virt);
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
    platform_expects(((uint64_t)0) != num);

    g_st->BootServices->SetMem(pmut_ptr, num, val);
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
    platform_expects(((uint64_t)0) != num);

    g_st->BootServices->CopyMem(pmut_dst, ((VOID *)src), num);
}

/**
 * <!-- description -->
 *   @brief Copies "num" bytes from "src" to "dst". If "src" or "dst" are
 *     NULL, returns LOADER_FAILURE, otherwise returns 0. Note that this function can
 *     be used to copy memory from userspace via an IOCTL.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_dst a pointer to the memory to copy to
 *   @param src a pointer to the memory to copy from
 *   @param num the number of bytes to copy
 *   @return If "src" or "dst" are NULL, returns LOADER_FAILURE, otherwise
 *     returns 0.
 */
NODISCARD int64_t
platform_copy_from_user(void *const pmut_dst, void const *const src, uint64_t const num) NOEXCEPT
{
    platform_expects(NULLPTR != pmut_dst);
    platform_expects(NULLPTR != src);
    platform_expects(((uint64_t)0) != num);

    g_st->BootServices->CopyMem(pmut_dst, ((VOID *)src), num);
    return LOADER_SUCCESS;
}

/**
 * <!-- description -->
 *   @brief Copies "num" bytes from "src" to "dst". If "src" or "dst" are
 *     NULL, returns LOADER_FAILURE, otherwise returns 0. Note that this function can
 *     be used to copy memory to userspace via an IOCTL.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_dst a pointer to the memory to copy to
 *   @param src a pointer to the memory to copy from
 *   @param num the number of bytes to copy
 *   @return If "src" or "dst" are NULL, returns LOADER_FAILURE, otherwise
 *     returns 0.
 */
NODISCARD int64_t
platform_copy_to_user(void *const pmut_dst, void const *const src, uint64_t const num) NOEXCEPT
{
    platform_expects(NULLPTR != pmut_dst);
    platform_expects(NULLPTR != src);
    platform_expects(((uint64_t)0) != num);

    g_st->BootServices->CopyMem(pmut_dst, ((VOID *)src), num);
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
    return arch_num_online_cpus();
}

/**
 * <!-- description -->
 *   @brief Executes a callback on a specific PP.
 *
 * <!-- inputs/outputs -->
 *   @param cpu the PP to execute the callback on
 *   @param callback the callback to call
 *   @param args the arguments for work_on_cpu_callback
 */
void
work_on_cpu(
    uint32_t const cpu, void *const callback, struct work_on_cpu_callback_args *const args) NOEXCEPT
{
    arch_work_on_cpu(cpu, callback, args);
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
    uint32_t cpu;

    for (cpu = 0; cpu < platform_num_online_cpus(); ++cpu) {
        struct work_on_cpu_callback_args args = {func, cpu, 0, 0};

        work_on_cpu(cpu, work_on_cpu_callback, &args);
        if (args.ret) {
            bferror("platform_per_cpu_func failed");
            return LOADER_FAILURE;
        }
    }

    return LOADER_SUCCESS;
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
platform_on_each_cpu(platform_per_cpu_func const func, uint32_t const order) NOEXCEPT
{
    int64_t ret;
    platform_expects(NULLPTR != func);

    if (PLATFORM_FORWARD == order) {
        ret = platform_on_each_cpu_forward(func);
    }
    else {
        bferror("PLATFORM_REVERSE currently not supported");
        ret = LOADER_FAILURE;
    }

    return ret;
}

/**
 * <!-- description -->
 *   @brief Dumps the contents of the VMM's ring buffer.
 */
void
platform_dump_vmm(void) NOEXCEPT
{
    uint64_t epos = g_pmut_mut_mk_debug_ring->epos;
    uint64_t spos = g_pmut_mut_mk_debug_ring->spos;

    if (!(HYPERVISOR_DEBUG_RING_SIZE > epos)) {
        epos = ((uint64_t)0);
    }

    if (spos == epos) {
        console_write("no debug data to dump\r\n");
        return;
    }

    while (spos != epos) {
        if (!(HYPERVISOR_DEBUG_RING_SIZE > spos)) {
            spos = ((uint64_t)0);
        }

        console_write_c(g_pmut_mut_mk_debug_ring->buf[spos]);
        ++spos;
    }

    console_write("\r\n");
}

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
    return arch_init();
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
