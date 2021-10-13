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
#include <intrinsic_cpuid.h>
#include <intrinsic_rdmsr.h>
#include <types.h>

/** @brief defines the CPUID leaf for vendor information */
#define CPUID_LEAF_VENDOR ((uint32_t)0x0)
/** @brief define the CPUID vendor ID #1 returned in EBX */
#define CPUID_VENDOR_EBX ((uint32_t)0x68747541)
/** @brief define the CPUID vendor ID #2 returned in ECX */
#define CPUID_VENDOR_ECX ((uint32_t)0x444d4163)
/** @brief define the CPUID vendor ID #3 returned in EDX */
#define CPUID_VENDOR_EDX ((uint32_t)0x69746e65)

/** @brief defines the CPUID leaf for feature information */
#define CPUID_LEAF_FEATURE ((uint32_t)0x1)
/** @brief define the CPUID feature bit for XSAVE */
#define CPUID_FEATURE_ECX_XSAVE (((uint32_t)1) << ((uint32_t)26))
/** @brief define the CPUID feature bit for OSXSAVE */
#define CPUID_FEATURE_ECX_OSXSAVE (((uint32_t)1) << ((uint32_t)27))

/** @brief defines the CPUID leaf for feature information */
#define CPUID_LEAF_EXT_FEATURE ((uint32_t)0x80000001)
/** @brief define the CPUID feature bit for VMX */
#define CPUID_EXT_FEATURE_ECX_SVM (((uint32_t)1) << ((uint32_t)2))

/** @brief defines the MSR_VM_CR MSR  */
#define MSR_VM_CR ((uint32_t)0xC0010114)
/** @brief defines the VM_CR_SVMDIS MSR field */
#define VM_CR_SVMDIS (((uint64_t)1) << ((uint64_t)4))

/** @brief defines the MSR_EFER MSR  */
#define MSR_EFER ((uint32_t)0xC0000080)
/** @brief defines the EFER_LMA MSR field */
#define EFER_LMA (((uint64_t)1) << ((uint64_t)10))
/** @brief defines the EFER_LME MSR field */
#define EFER_LME (((uint64_t)1) << ((uint64_t)8))

/**
 * <!-- description -->
 *   @brief Check we're running on an AMD processor.
 *
 * <!-- inputs/outputs -->
 *   @return Return 0 if running on an AMD processor, LOADER_FAILURE
 *     otherwise.
 */
NODISCARD static inline int64_t
check_for_amd(void) NOEXCEPT
{
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;

    eax = CPUID_LEAF_VENDOR;
    ecx = 0U;
    intrinsic_cpuid(&eax, &ebx, &ecx, &edx);

    if (CPUID_VENDOR_EBX != ebx) {
        bferror_x32("cpu is vendor is not AuthenticAMD", ebx);
        return LOADER_FAILURE;
    }

    if (CPUID_VENDOR_ECX != ecx) {
        bferror_x32("cpu is vendor is not AuthenticAMD", ecx);
        return LOADER_FAILURE;
    }

    if (CPUID_VENDOR_EDX != edx) {
        bferror_x32("cpu is vendor is not AuthenticAMD", edx);
        return LOADER_FAILURE;
    }

    return LOADER_SUCCESS;
}

/**
 * <!-- description -->
 *   @brief Check if the cpu supports needed SVM.
 *
 * <!-- inputs/outputs -->
 *   @return Returns 0 on success, LOADER_FAILURE otherwise.
 */
NODISCARD static inline int64_t
check_for_svm(void) NOEXCEPT
{
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;

    eax = CPUID_LEAF_EXT_FEATURE;
    ecx = 0U;
    intrinsic_cpuid(&eax, &ebx, &ecx, &edx);

    if ((ecx & CPUID_EXT_FEATURE_ECX_SVM) == 0U) {
        bferror_x32("cpu does not support SVM", ecx);
        return LOADER_FAILURE;
    }

    return LOADER_SUCCESS;
}

/**
 * <!-- description -->
 *   @brief Check if SVM support has been disabled
 *
 * <!-- inputs/outputs -->
 *   @return Returns 0 on success, LOADER_FAILURE otherwise.
 */
NODISCARD static inline int64_t
check_for_svm_disabled(void) NOEXCEPT
{
    uint64_t msr = intrinsic_rdmsr(MSR_VM_CR);

    if ((msr & VM_CR_SVMDIS) != ((uint64_t)0)) {
        bferror_x64("SVM has been disabled in BIOS", msr);
        return LOADER_FAILURE;
    }

    return LOADER_SUCCESS;
}

/**
 * <!-- description -->
 *   @brief Check the configuration of EFER
 *
 * <!-- inputs/outputs -->
 *   @return Returns 0 on success, LOADER_FAILURE otherwise.
 */
NODISCARD static inline int64_t
check_the_configuration_of_efer(void) NOEXCEPT
{
    uint64_t msr = intrinsic_rdmsr(MSR_EFER);

    if ((msr & EFER_LMA) == ((uint64_t)0)) {
        bferror_x64("The OS is not in long mode", msr);
        return LOADER_FAILURE;
    }

    if ((msr & EFER_LME) == ((uint64_t)0)) {
        bferror_x64("Long mode not enabled", msr);
        return LOADER_FAILURE;
    }

    return LOADER_SUCCESS;
}

/**
 * <!-- description -->
 *   @brief Check if the cpu supports XSAVE.
 *
 * <!-- inputs/outputs -->
 *   @return Returns 0 on success, LOADER_FAILURE otherwise.
 */
NODISCARD static inline int64_t
check_for_xsave(void) NOEXCEPT
{
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;

    eax = CPUID_LEAF_FEATURE;
    ecx = 0U;
    intrinsic_cpuid(&eax, &ebx, &ecx, &edx);

    if ((ecx & CPUID_FEATURE_ECX_XSAVE) == 0U) {
        bferror_x32("cpu does not support XSAVE", ecx);
        return LOADER_FAILURE;
    }

    if ((ecx & CPUID_FEATURE_ECX_OSXSAVE) == 0U) {
        bferror_x32("cpu does not support CR4.OSXSAVE", ecx);
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
    if (check_for_amd()) {
        bferror("check_for_amd failed");
        return LOADER_FAILURE;
    }

    if (check_for_svm()) {
        bferror("check_for_svm failed");
        return LOADER_FAILURE;
    }

    if (check_for_svm_disabled()) {
        bferror("check_for_svm_disabled failed");
        return LOADER_FAILURE;
    }

    if (check_the_configuration_of_efer()) {
        bferror("check_the_configuration_of_efer failed");
        return LOADER_FAILURE;
    }

    if (check_for_xsave()) {
        bferror("check_for_xsave failed");
        return LOADER_FAILURE;
    }

    return LOADER_SUCCESS;
}
