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
#define CPUID_VENDOR_EBX ((uint32_t)0x756e6547)
/** @brief define the CPUID vendor ID #2 returned in ECX */
#define CPUID_VENDOR_ECX ((uint32_t)0x6C65746E)
/** @brief define the CPUID vendor ID #3 returned in EDX */
#define CPUID_VENDOR_EDX ((uint32_t)0x49656E69)

/** @brief defines the CPUID leaf for feature information */
#define CPUID_LEAF_FEATURE ((uint32_t)0x1)
/** @brief define the CPUID feature bit for VMX */
#define CPUID_FEATURE_ECX_VMX (((uint32_t)1) << ((uint32_t)5))
/** @brief define the CPUID feature bit for XSAVE */
#define CPUID_FEATURE_ECX_XSAVE (((uint32_t)1) << ((uint32_t)26))

/** @brief defines the CPUID leaf for xsave information */
#define CPUID_LEAF_XSAVE ((uint32_t)0xD)
/** @brief define the CPUID bit indicating support for xsaves/xrstors */
#define CPUID_XSAVE_EAX_XSAVES_XRSTORS (((uint32_t)1) << ((uint32_t)3))

/** @brief defines the MSR address for feature information */
#define MSR_IA32_FEATURE_CTRL ((uint32_t)0x3A)
/** @brief defines the MSR feature VMX enabled bit */
#define FEATURE_CTRL_VMX_ENABLED_OUTSIDE_SMX (((uint64_t)1) << ((uint64_t)2))

/** @brief defines the MSR address for VMX information */
#define MSR_IA32_VMX_BASIC ((uint32_t)0x480)
/** @brief defines the supported physical address size */
#define VMX_BASIC_PHYS_ADDR_SIZE (((uint64_t)1) << ((uint64_t)48))
/** @brief defines the VMX memory type */
#define VMX_BASIC_MEMORY_TYPE ((uint64_t)0x003C000000000000)
/** @brief defines the VMX memory type for write back */
#define VMX_BASIC_MEMORY_TYPE_WB ((uint64_t)0x0018000000000000)
/** @brief defines the MSR VMX true controls enabled bit */
#define VMX_BASIC_TRUE_CTRLS (((uint64_t)1) << ((uint64_t)55))

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
 *   @brief Check we're running on an Intel processor.
 *
 * <!-- inputs/outputs -->
 *   @return Return 0 if running on an Intel processor, LOADER_FAILURE
 *     otherwise.
 */
static inline int64_t
check_for_intel(void)
{
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;

    eax = CPUID_LEAF_VENDOR;
    ecx = 0U;
    intrinsic_cpuid(&eax, &ebx, &ecx, &edx);

    if (CPUID_VENDOR_EBX != ebx) {
        BFERROR("cpu is vendor is not GenuineIntel: 0x%08u\n", ebx);
        return LOADER_FAILURE;
    }

    if (CPUID_VENDOR_ECX != ecx) {
        BFERROR("cpu is vendor is not GenuineIntel: 0x%08u\n", ecx);
        return LOADER_FAILURE;
    }

    if (CPUID_VENDOR_EDX != edx) {
        BFERROR("cpu is vendor is not GenuineIntel: 0x%08u\n", edx);
        return LOADER_FAILURE;
    }

    return LOADER_SUCCESS;
}

/**
 * <!-- description -->
 *   @brief Check if the cpu supports needed VMX and XSAVE.
 *
 * <!-- inputs/outputs -->
 *   @return Returns 0 on success, LOADER_FAILURE otherwise.
 */
static inline int64_t
check_for_vmx_and_xsave(void)
{
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;

    eax = CPUID_LEAF_FEATURE;
    ecx = 0U;
    intrinsic_cpuid(&eax, &ebx, &ecx, &edx);

    if ((ecx & CPUID_FEATURE_ECX_VMX) == 0U) {
        BFERROR("cpu does not support VT-x: 0x%08x\n", ecx);
        return LOADER_FAILURE;
    }

    if ((ecx & CPUID_FEATURE_ECX_XSAVE) == 0U) {
        BFERROR("cpu does not support XSAVE: 0x%08x\n", ecx);
        return LOADER_FAILURE;
    }

    return LOADER_SUCCESS;
}

/**
 * <!-- description -->
 *   @brief Check that XSAVES is supported and that neither xcr0 nor
 *     ia32_xss msr allow bits 63:32 to be 1.
 *
 * <!-- inputs/outputs -->
 *   @return Return 0 on success, LOADER_FAILURE otherwise.
 */
static inline int64_t
check_for_xsaves_and_xrstors(void)
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

    eax = CPUID_LEAF_XSAVE;
    ecx = 1U;
    intrinsic_cpuid(&eax, &ebx, &ecx, &edx);

    if ((eax & CPUID_XSAVE_EAX_XSAVES_XRSTORS) == 0U) {
        BFERROR("cpu does not support XSAVES/XRSTORS: 0x%08x\n", eax);
        return LOADER_FAILURE;
    }

    if (edx != 0U) {
        BFERROR("cpu allows setting upper 32 bits in ia32_xss: 0x%08x\n", edx);
        return LOADER_FAILURE;
    }

    return LOADER_SUCCESS;
}

/**
 * <!-- description -->
 *   @brief Check that BIOS hasn't locked us out of VMX.
 *
 * <!-- inputs/outputs -->
 *   @return Return 0 if VMX is usable, LOADER_FAILURE otherwise.
 */
static inline int64_t
check_for_vmx_disabled(void)
{
    uint64_t msr = intrinsic_rdmsr(MSR_IA32_FEATURE_CTRL);

    if ((msr & FEATURE_CTRL_VMX_ENABLED_OUTSIDE_SMX) == ((uint64_t)0)) {
        BFERROR("VT-x has been disabled in BIOS: 0x%016" PRIx64 "\n", msr);
        return LOADER_FAILURE;
    }

    return LOADER_SUCCESS;
}

/**
 * <!-- description -->
 *   @brief Check that the VT-x implementation support the TRUE controls
 *
 * <!-- inputs/outputs -->
 *   @return Return 0 on success, LOADER_FAILURE otherwise.
 */
static inline int64_t
check_vmx_capabilities(void)
{
    uint64_t msr = intrinsic_rdmsr(MSR_IA32_VMX_BASIC);

    if ((msr & VMX_BASIC_PHYS_ADDR_SIZE) != ((uint64_t)0)) {
        BFERROR("VT-x address size not supported: 0x%016" PRIx64 "\n", msr);
        return LOADER_FAILURE;
    }

    if ((msr & VMX_BASIC_MEMORY_TYPE) != VMX_BASIC_MEMORY_TYPE_WB) {
        BFERROR("VT-x memory type not supported: 0x%016" PRIx64 "\n", msr);
        return LOADER_FAILURE;
    }

    if ((msr & VMX_BASIC_TRUE_CTRLS) == ((uint64_t)0)) {
        BFERROR("VT-x true controls not supported: 0x%016" PRIx64 "\n", msr);
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
 *   @brief This function checks to see if Intel VT-x support is available on
 *     the currently running CPU
 *
 * <!-- inputs/outputs -->
 *   @return Returns 0 on success
 */
int64_t
check_for_hve_support(void)
{
    if (check_for_intel()) {
        BFERROR("check_for_intel failed\n");
        return LOADER_FAILURE;
    }

    if (check_for_vmx_and_xsave()) {
        BFERROR("check_for_vmx_and_xsave failed\n");
        return LOADER_FAILURE;
    }

    if (check_for_xsaves_and_xrstors()) {
        BFERROR("check_for_xsaves_and_xrstors failed\n");
        return LOADER_FAILURE;
    }

    if (check_for_vmx_disabled()) {
        BFERROR("check_for_vmx_disabled failed\n");
        return LOADER_FAILURE;
    }

    if (check_vmx_capabilities()) {
        BFERROR("check_vmx_capabilities failed\n");
        return LOADER_FAILURE;
    }

    if (check_the_configuration_of_efer()) {
        BFERROR("check_the_configuration_of_efer failed\n");
        return LOADER_FAILURE;
    }

    /**
     * TODO:
     * - CR0, CR4 and FEATURE_CONTROL bits need to be checked as well
     */

    return LOADER_SUCCESS;
}
