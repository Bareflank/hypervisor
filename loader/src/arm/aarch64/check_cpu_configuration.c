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

#include <constants.h>
#include <debug.h>
#include <read_currentel.h>
#include <types.h>

/** @brief define the expected value of CurrentEL */
#define CURRENTEL_EXPECTED ((uint64_t)0x8)

/**
 * NOTE:
 * - ARMv8 doesn't really have the same thing as CPUID on x86. Instead, it
 *   has ID_ fields that can be read to get feature information that we care
 *   about. Due to this issue, there isn't a clean way to ensure the specific
 *   CPU we are executing on is supported, but instead we can only check
 *   to ensure specific features are supported.
 * - ARMv8 has something called Virtualization Host Extensions (VHE). This
 *   was added in ARMv8.1. ARMv8.0 (i.e. the original) has had virtualization
 *   support from launch. The problem was, this initial virtualization
 *   support didn't include support for hosted (i.e. type 2) hypervisors. So
 *   hypervisors like Xen, HyperV and ESXi all worked great, but KVM needed a
 *   small stub inside of EL2 to forward traps to EL1 since you could not run
 *   the Linux kernel in EL2 which is how KVM works (as it is hosted). VHE
 *   adds support for this but allowing not only EL1 <-> EL0 but also
 *   EL2 <-> EL0, which is what allows Linux to run in EL2.
 * - Bareflank's microkernel is a Type 1, meaning it is not hosted, so it
 *   does not need VHE support. On Intel, each extension runs in Ring 3.
 *   This is because rings 1 and 2 were removed. On ARM, extensions run in
 *   EL1, and any operations that an extension performs that are priviledged
 *   are trapped by the microkernel and handled. This is mainly because on
 *   CPUs that do not have VHE, the microkernel cannot run extensions in EL0.
 *   Even if it could, there would be no need and doing so would only reduce
 *   the overall performance of the extension as more operations would have
 *   to be moved to the microkernel.
 * - Note that one limitation of using EL2 without VHE is that the hypervisor
 *   cannot use the upper half of the canonical address space. For Bareflank,
 *   this is a non-issue as it doesn't use this address space anyways. It
 *   should be noted however that if late-launch is ever supported, care will
 *   need to be taken to ensure kernel addresses from EL1 are not used by
 *   the microkernel, which is something the x86 version of the loader does
 *   when late-launch is used.
 * - For now, the loader assumes we are running on ARMv8 or higher, and we
 *   check to ensure the loader is running in EL2. VHE is not enabled by the
 *   loader so it is never used. Any additional features that are needed by the
 *   microkernel can be checked here, but for now, it is pretty simple as we
 *   assume that we only have ARMv8.0.
 */

/**
 * <!-- description -->
 *   @brief Check we're running on a supported ARM processor
 *
 * <!-- inputs/outputs -->
 *   @return Return 0 if running on a supported ARM processor, LOADER_FAILURE
 *     otherwise.
 */
NODISCARD static inline int64_t
check_for_el2(void) NOEXCEPT
{
    if (CURRENTEL_EXPECTED != read_currentel()) {
        bferror("cpu is not in EL2");
        return LOADER_FAILURE;
    }

    return LOADER_SUCCESS;
}

/**
 * <!-- description -->
 *   @brief This function checks to see if the CPU is supported as well as
 *     it's system configuration.
 *
 * <!-- inputs/outputs -->
 *   @return Returns 0 on success
 */
NODISCARD int64_t
check_cpu_configuration(void) NOEXCEPT
{
    if (check_for_el2()) {
        bferror("check_for_el2 failed");
        return LOADER_FAILURE;
    }

    return LOADER_SUCCESS;
}
