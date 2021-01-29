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

/** @brief defines the CPUID leaf for xsave information */
#define CPUID_LEAF_XSAVE ((uint32_t)0xD)

/** @brief defines the CPUID leaf for feature information */
#define CPUID_LEAF_EXT_FEATURE ((uint32_t)0x80000001)
/** @brief define the CPUID feature bit for VMX */
#define CPUID_EXT_FEATURE_ECX_SVM (((uint32_t)1) << ((uint32_t)2))

/** @brief defines the MSR_IA32_VM_CR MSR  */
#define MSR_IA32_VM_CR ((uint32_t)0xC0010114)
/** @brief defines the VM_CR_SVMDIS MSR field */
#define VM_CR_SVMDIS (((uint64_t)1) << ((uint64_t)4))

/** @brief defines the MSR_IA32_EFER MSR  */
#define MSR_IA32_EFER ((uint32_t)0xC0000080)
/** @brief defines the EFER_NXE MSR field */
#define EFER_NXE (((uint64_t)1) << ((uint64_t)11))
/** @brief defines the EFER_LMA MSR field */
#define EFER_LMA (((uint64_t)1) << ((uint64_t)10))
/** @brief defines the EFER_LME MSR field */
#define EFER_LME (((uint64_t)1) << ((uint64_t)8))
/** @brief defines the EFER_SCE MSR field */
#define EFER_SCE (((uint64_t)1) << ((uint64_t)0))

/**
 * <!-- description -->
 *   @brief Check we're running on an AMD processor.
 *
 * <!-- inputs/outputs -->
 *   @return Return 0 if running on an AMD processor, LOADER_FAILURE
 *     otherwise.
 */
static inline int64_t
check_for_amd(void)
{
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;

    eax = CPUID_LEAF_VENDOR;
    ecx = 0U;
    intrinsic_cpuid(&eax, &ebx, &ecx, &edx);

    if (CPUID_VENDOR_EBX != ebx) {
        BFERROR("cpu is vendor is not AuthenticAMD: 0x%08x\n", ebx);
        return LOADER_FAILURE;
    }

    if (CPUID_VENDOR_ECX != ecx) {
        BFERROR("cpu is vendor is not AuthenticAMD: 0x%08x\n", ecx);
        return LOADER_FAILURE;
    }

    if (CPUID_VENDOR_EDX != edx) {
        BFERROR("cpu is vendor is not AuthenticAMD: 0x%08x\n", edx);
        return LOADER_FAILURE;
    }

    return LOADER_SUCCESS;
}

/**
 * <!-- description -->
 *   @brief Check if the cpu supports needed XSAVE.
 *
 * <!-- inputs/outputs -->
 *   @return Returns 0 on success, LOADER_FAILURE otherwise.
 */
static inline int64_t
check_for_xsave(void)
{
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;

    eax = CPUID_LEAF_FEATURE;
    ecx = 0U;
    intrinsic_cpuid(&eax, &ebx, &ecx, &edx);

    if ((ecx & CPUID_FEATURE_ECX_XSAVE) == 0U) {
        BFERROR("cpu does not support XSAVE: 0x%08x\n", ecx);
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
static inline int64_t
check_for_svm(void)
{
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;

    eax = CPUID_LEAF_EXT_FEATURE;
    ecx = 0U;
    intrinsic_cpuid(&eax, &ebx, &ecx, &edx);

    if ((ecx & CPUID_EXT_FEATURE_ECX_SVM) == 0U) {
        BFERROR("cpu does not support SVM: 0x%08x\n", ecx);
        return LOADER_FAILURE;
    }

    return LOADER_SUCCESS;
}

/**
 * <!-- description -->
 *   @brief Check that xcr0 does not allow bits 63:32 of xcr0 to be 1.
 *
 * <!-- inputs/outputs -->
 *   @return Return 0 on success, LOADER_FAILURE otherwise.
 */
static inline int64_t
check_verify_xsave_valid_bits(void)
{
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;

    eax = CPUID_LEAF_XSAVE;
    ecx = 0U;
    intrinsic_cpuid(&eax, &ebx, &ecx, &edx);

    if (((uint64_t)ecx) > HYPERVISOR_PAGE_SIZE) {
        BFERROR("the size of xsave is unsupported: 0x%08x\n", ecx);
        return LOADER_FAILURE;
    }

    if (edx != 0U) {
        BFERROR("cpu allows setting upper 32 bits in xcr0: 0x%08x\n", edx);
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
static inline int64_t
check_for_svm_disabled(void)
{
    uint64_t msr = intrinsic_rdmsr(MSR_IA32_VM_CR);

    if ((msr & VM_CR_SVMDIS) != ((uint64_t)0)) {
        BFERROR("SVM has been disabled in BIOS: 0x%016" PRIx64 "\n", msr);
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
static inline int64_t
check_the_configuration_of_efer(void)
{
    uint64_t msr = intrinsic_rdmsr(MSR_IA32_EFER);

    if ((msr & EFER_NXE) == ((uint64_t)0)) {
        BFERROR("No-Execute page support not enabled: 0x%016" PRIx64 "\n", msr);
        return LOADER_FAILURE;
    }

    if ((msr & EFER_LMA) == ((uint64_t)0)) {
        BFERROR("The OS is not in long mode: 0x%016" PRIx64 "\n", msr);
        return LOADER_FAILURE;
    }

    if ((msr & EFER_LME) == ((uint64_t)0)) {
        BFERROR("Long mode not enabled: 0x%016" PRIx64 "\n", msr);
        return LOADER_FAILURE;
    }

    if ((msr & EFER_SCE) == ((uint64_t)0)) {
        BFERROR("SYSCALL support not enabled: 0x%016" PRIx64 "\n", msr);
        return LOADER_FAILURE;
    }

    return LOADER_SUCCESS;
}

/**
 * <!-- description -->
 *   @brief This function checks to see if AMD SVM support is available on
 *     the currently running CPU
 *
 * <!-- inputs/outputs -->
 *   @return Returns 0 on success
 */
int64_t
check_for_hve_support(void)
{
    if (check_for_amd()) {
        BFERROR("check_for_amd failed\n");
        return LOADER_FAILURE;
    }

    if (check_for_xsave()) {
        BFERROR("check_for_xsave failed\n");
        return LOADER_FAILURE;
    }

    if (check_for_svm()) {
        BFERROR("check_for_svm failed\n");
        return LOADER_FAILURE;
    }

    if (check_verify_xsave_valid_bits()) {
        BFERROR("check_verify_xsave_valid_bits failed\n");
        return LOADER_FAILURE;
    }

    if (check_for_svm_disabled()) {
        BFERROR("check_for_svm_disabled failed\n");
        return LOADER_FAILURE;
    }

    if (check_the_configuration_of_efer()) {
        BFERROR("check_the_configuration_of_efer failed\n");
        return LOADER_FAILURE;
    }

    return LOADER_SUCCESS;
}
