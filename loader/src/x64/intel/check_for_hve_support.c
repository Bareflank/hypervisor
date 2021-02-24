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

/** @brief defines the CPUID leaf for structured extended feature information */
#define CPUID_LEAF_STRUCT_EXT_FEATURE ((uint32_t)0x7)
/** @brief define the CPUID feature bit for SMEP */
#define CPUID_STRUCT_EXT_FEATURE_EBX_SMEP (((uint32_t)1) << ((uint32_t)7))
/** @brief define the CPUID feature bit for SMAP */
#define CPUID_STRUCT_EXT_FEATURE_EBX_SMAP (((uint32_t)1) << ((uint32_t)20))

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
/** @brief defines the EFER_LMA MSR field */
#define EFER_LMA (((uint64_t)1) << ((uint64_t)10))
/** @brief defines the EFER_LME MSR field */
#define EFER_LME (((uint64_t)1) << ((uint64_t)8))

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
        bferror_x32("cpu is vendor is not GenuineIntel", ebx);
        return LOADER_FAILURE;
    }

    if (CPUID_VENDOR_ECX != ecx) {
        bferror_x32("cpu is vendor is not GenuineIntel", ecx);
        return LOADER_FAILURE;
    }

    if (CPUID_VENDOR_EDX != edx) {
        bferror_x32("cpu is vendor is not GenuineIntel", edx);
        return LOADER_FAILURE;
    }

    return LOADER_SUCCESS;
}

/**
 * <!-- description -->
 *   @brief Check if the cpu supports needed VMX.
 *
 * <!-- inputs/outputs -->
 *   @return Returns 0 on success, LOADER_FAILURE otherwise.
 */
static inline int64_t
check_for_vmx(void)
{
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;

    eax = CPUID_LEAF_FEATURE;
    ecx = 0U;
    intrinsic_cpuid(&eax, &ebx, &ecx, &edx);

    if ((ecx & CPUID_FEATURE_ECX_VMX) == 0U) {
        bferror_x32("cpu does not support VT-x", ecx);
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
        bferror_x64("VT-x has been disabled in BIOS", msr);
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
        bferror_x64("VT-x address size not supported", msr);
        return LOADER_FAILURE;
    }

    if ((msr & VMX_BASIC_MEMORY_TYPE) != VMX_BASIC_MEMORY_TYPE_WB) {
        bferror_x64("VT-x memory type not supported", msr);
        return LOADER_FAILURE;
    }

    if ((msr & VMX_BASIC_TRUE_CTRLS) == ((uint64_t)0)) {
        bferror_x64("VT-x true controls not supported", msr);
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
 *   @brief Check if the cpu supports needed SMEP/SMAP.
 *
 * <!-- inputs/outputs -->
 *   @return Returns 0 on success, LOADER_FAILURE otherwise.
 */
static inline int64_t
check_for_smep_smap(void)
{
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;

    eax = CPUID_LEAF_STRUCT_EXT_FEATURE;
    ecx = 0U;
    intrinsic_cpuid(&eax, &ebx, &ecx, &edx);

    if ((ebx & CPUID_STRUCT_EXT_FEATURE_EBX_SMEP) == 0U) {
        bferror_x32("cpu does not support SMEP", ebx);
        return LOADER_FAILURE;
    }

    if ((ebx & CPUID_STRUCT_EXT_FEATURE_EBX_SMAP) == 0U) {
        bferror_x32("cpu does not support SMAP", ebx);
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
        bferror("check_for_intel failed");
        return LOADER_FAILURE;
    }

    if (check_for_vmx()) {
        bferror("check_for_vmx failed");
        return LOADER_FAILURE;
    }

    if (check_for_vmx_disabled()) {
        bferror("check_for_vmx_disabled failed");
        return LOADER_FAILURE;
    }

    if (check_vmx_capabilities()) {
        bferror("check_vmx_capabilities failed");
        return LOADER_FAILURE;
    }

    if (check_the_configuration_of_efer()) {
        bferror("check_the_configuration_of_efer failed");
        return LOADER_FAILURE;
    }

    if (check_for_smep_smap()) {
        bferror("check_for_smep_smap failed");
        return LOADER_FAILURE;
    }

    return LOADER_SUCCESS;
}
