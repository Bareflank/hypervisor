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
#include <work_on_cpu_callback_args.h>

// clang-format on

#define BF_TAG 'BFLK'

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
    NT_ASSERT(test);
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
    NT_ASSERT(test);
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
    void *ret;

    if (0 == size) {
        bferror("invalid number of bytes (i.e., size)");
        return NULLPTR;
    }

    ret = ExAllocatePoolWithTag(NonPagedPool, size, BF_TAG);
    if (NULLPTR == ret) {
        bferror("vmalloc failed");
        return NULLPTR;
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
NODISCARD void *
platform_alloc_contiguous(uint64_t const size) NOEXCEPT
{
    void *ret;

    if (0 == size) {
        bferror("invalid number of bytes (i.e., size)");
        return NULLPTR;
    }

    PHYSICAL_ADDRESS addr;
    addr.QuadPart = MAXULONG64;

    ret = MmAllocateContiguousMemory(size, addr);
    if (NULLPTR == ret) {
        bferror("kmalloc failed");
        return NULLPTR;
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
platform_free(void const *const ptr, uint64_t const size) NOEXCEPT
{
    (void)size;

    if (NULLPTR != ptr) {
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
platform_free_contiguous(void const *const ptr, uint64_t const size) NOEXCEPT
{
    (void)size;

    if (NULLPTR != ptr) {
        MmFreeContiguousMemory((void *)ptr);
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
 */
void
platform_memset(void *const ptr, uint8_t const val, uint64_t const num) NOEXCEPT
{
    platform_expects(NULLPTR != ptr);
    RtlFillMemory(ptr, num, val);
}

/**
 * <!-- description -->
 *   @brief Copies "num" bytes from "src" to "dst". If "src" or "dst" are
 *     NULLPTR, returns LOADER_FAILURE, otherwise returns 0.
 *
 * <!-- inputs/outputs -->
 *   @param dst a pointer to the memory to copy to
 *   @param src a pointer to the memory to copy from
 *   @param num the number of bytes to copy
 */
void
platform_memcpy(void *const dst, void const *const src, uint64_t const num) NOEXCEPT
{
    platform_expects(NULLPTR != dst);
    platform_expects(NULLPTR != src);

    RtlCopyMemory(dst, src, num);
}

/**
 * <!-- description -->
 *   @brief Copies "num" bytes from "src" to "dst". If "src" or "dst" are
 *     NULLPTR, returns FAILURE, otherwise returns 0. Note that this function can
 *     be used to copy memory from userspace via an IOCTL.
 *
 * <!-- inputs/outputs -->
 *   @param dst a pointer to the memory to copy to
 *   @param src a pointer to the memory to copy from
 *   @param num the number of bytes to copy
 *   @return If "src" or "dst" are NULLPTR, returns FAILURE, otherwise
 *     returns 0.
 */
NODISCARD int64_t
platform_copy_from_user(void *const dst, void const *const src, uint64_t const num) NOEXCEPT
{
    PMDL mdl = NULL;
    PVOID buffer = NULL;

    platform_expects(NULLPTR != dst);
    platform_expects(NULLPTR != src);

    try {
        ProbeForRead((void *)src, num, sizeof(UCHAR));
    }
    except(EXCEPTION_EXECUTE_HANDLER)
    {
        bferror("ProbeForRead failed\n");
        goto probeforeread_failed;
    }

    mdl = IoAllocateMdl((void *)src, (ULONG)num, FALSE, TRUE, NULL);
    if (!mdl) {
        bferror("IoAllocateMdl failed\n");
        goto ioallocatemdl_failed;
    }

    try {
        MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
    }
    except(EXCEPTION_EXECUTE_HANDLER)
    {
        bferror("MmProbeAndLockPages failed\n");
        goto mmprobeandlockpages_failed;
    }

    buffer = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute);
    if (NULL == buffer) {
        bferror("MmGetSystemAddressForMdlSafe failed\n");
        goto mmgetsystemaddressformdlsafe_failed;
    }

    RtlCopyMemory(dst, buffer, num);

    MmUnlockPages(mdl);
    IoFreeMdl(mdl);

    return LOADER_SUCCESS;

mmgetsystemaddressformdlsafe_failed:
    MmUnlockPages(mdl);
mmprobeandlockpages_failed:
    IoFreeMdl(mdl);
ioallocatemdl_failed:
probeforeread_failed:

    return LOADER_FAILURE;
}

/**
 * <!-- description -->
 *   @brief Copies "num" bytes from "src" to "dst". If "src" or "dst" are
 *     NULLPTR, returns FAILURE, otherwise returns 0. Note that this function can
 *     be used to copy memory to userspace via an IOCTL.
 *
 * <!-- inputs/outputs -->
 *   @param dst a pointer to the memory to copy to
 *   @param src a pointer to the memory to copy from
 *   @param num the number of bytes to copy
 *   @return If "src" or "dst" are NULLPTR, returns FAILURE, otherwise
 *     returns 0.
 */
NODISCARD int64_t
platform_copy_to_user(void *const dst, void const *const src, uint64_t const num) NOEXCEPT
{
    PMDL mdl = NULL;
    PVOID buffer = NULL;

    platform_expects(NULLPTR != dst);
    platform_expects(NULLPTR != src);

    try {
        ProbeForWrite((void *)dst, num, sizeof(UCHAR));
    }
    except(EXCEPTION_EXECUTE_HANDLER)
    {
        bferror("ProbeForWrite failed\n");
        goto probeforeread_failed;
    }

    mdl = IoAllocateMdl((void *)dst, (ULONG)num, FALSE, TRUE, NULL);
    if (!mdl) {
        bferror("IoAllocateMdl failed\n");
        goto ioallocatemdl_failed;
    }

    try {
        MmProbeAndLockPages(mdl, UserMode, IoWriteAccess);
    }
    except(EXCEPTION_EXECUTE_HANDLER)
    {
        bferror("MmProbeAndLockPages failed\n");
        goto mmprobeandlockpages_failed;
    }

    buffer = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute);
    if (NULL == buffer) {
        bferror("MmGetSystemAddressForMdlSafe failed\n");
        goto mmgetsystemaddressformdlsafe_failed;
    }

    RtlCopyMemory(buffer, src, num);

    MmUnlockPages(mdl);
    IoFreeMdl(mdl);

    return LOADER_SUCCESS;

mmgetsystemaddressformdlsafe_failed:
    MmUnlockPages(mdl);
mmprobeandlockpages_failed:
    IoFreeMdl(mdl);
ioallocatemdl_failed:
probeforeread_failed:

    return LOADER_FAILURE;
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
    return ((uint32_t)KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS));
}

/**
 * <!-- description -->
 *   @brief This function is called when the user calls platform_on_each_cpu.
 *     On each iteration of the CPU, this function calls the user provided
 *     callback with the signature that we perfer.
 *
 * <!-- inputs/outputs -->
 *   @param DPC ignored
 *   @param DeferredContext stores the params needed to execute the callback
 *   @param SystemArgument1 ignored
 *   @param SystemArgument2 ignored
 */
VOID
work_on_cpu_callback(
    KDPC *DPC, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2) NOEXCEPT
{
    struct work_on_cpu_callback_args *args = ((struct work_on_cpu_callback_args *)DeferredContext);

    (void)DPC;
    (void)SystemArgument1;
    (void)SystemArgument2;

    args->ret = args->func(args->cpu);
    args->done = 1;
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
    uint32_t const cpu,
    PKDEFERRED_ROUTINE const callback,
    struct work_on_cpu_callback_args *const args) NOEXCEPT
{
    NTSTATUS status;
    PROCESSOR_NUMBER ProcNumber;
    KDPC DPC;

    status = KeGetProcessorNumberFromIndex(((ULONG)cpu), &ProcNumber);
    if (!NT_SUCCESS(status)) {
        bferror_x64("KeGetProcessorNumberFromIndex failed", status);
        args->ret = LOADER_FAILURE;
    }

    KeInitializeDpc(&DPC, callback, args);

    status = KeSetTargetProcessorDpcEx(&DPC, &ProcNumber);
    if (!NT_SUCCESS(status)) {
        bferror_x64("KeSetTargetProcessorDpcEx failed", status);
        args->ret = LOADER_FAILURE;
    }

    if (!KeInsertQueueDpc(&DPC, NULL, NULL)) {
        bferror_x64("KeInsertQueueDpc failed", status);
        args->ret = LOADER_FAILURE;
    }

    while (0 == args->done) {
    }
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
    uint32_t cpu;

    for (cpu = platform_num_online_cpus(); cpu > 0; --cpu) {
        struct work_on_cpu_callback_args args = {func, cpu - 1, 0, 0};

        work_on_cpu(cpu - 1, work_on_cpu_callback, &args);
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

    if (PLATFORM_FORWARD == order) {
        ret = platform_on_each_cpu_forward(func);
    }
    else {
        ret = platform_on_each_cpu_reverse(func);
    }

    return ret;
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
{}

/**
 * <!-- description -->
 *   @brief Marks the current GDT as read-only
 */
void
platform_mark_gdt_readonly(void) NOEXCEPT
{}
