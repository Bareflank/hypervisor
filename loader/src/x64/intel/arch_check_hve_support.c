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

#include <loader.h>
#include <loader_arch.h>
#include <loader_debug.h>
#include <loader_global_resources.h>
#include <loader_intrinsics.h>
#include <loader_platform.h>
#include <loader_types.h>

#define CPUID_LEAF_VENDOR 0x0U
#define CPUID_VENDOR_EBX 0x756e6547U /* "Genu" */
#define CPUID_VENDOR_ECX 0x6C65746EU /* "ntel" */
#define CPUID_VENDOR_EDX 0x49656E69U /* "ineI" */

#define CPUID_LEAF_FEATURE 0x1U
#define CPUID_FEATURE_ECX_VMX (1ULL << 5U)
#define CPUID_FEATURE_ECX_XSAVE (1ULL << 26U)

#define CPUID_LEAF_XSAVE 0xDU
#define CPUID_XSAVE0_EDX_UPPER_XCR0 0U
#define CPUID_XSAVE1_EAX_XSAVES (1ULL << 3U)
#define CPUID_XSAVE1_EDX_UPPER_IA32_XSS 0U

#define MSR_IA32_FEATURE_CTRL 0x3AU
#define FEATURE_CTRL_LOCKED (1ULL << 0U)
#define FEATURE_CTRL_VMX_ENABLED_INSIDE_SMX (1ULL << 1U)
#define FEATURE_CTRL_VMX_ENABLED_OUTSIDE_SMX (1ULL << 2U)

#define MSR_IA32_VMX_BASIC 0x480U
#define VMX_BASIC_TRUE_CTRLS (1ULL << 55)

/**
 * <!-- description -->
 *   @brief Check we're running on an Intel processor.
 *
 * <!-- inputs/outputs -->
 *   @return Return 0 if running on an Intel processor, FAILURE otherwise.
 */
static inline int64_t
check_cpuid_vendor(void)
{
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;

    eax = CPUID_LEAF_VENDOR;
    ecx = 0U;

    arch_cpuid(&eax, &ebx, &ecx, &edx);

    if (CPUID_VENDOR_EBX != ebx) {
        BFALERT("cpu is vendor is not GenuineIntel");
        return FAILURE;
    }

    if (CPUID_VENDOR_ECX != ecx) {
        BFALERT("cpu is vendor is not GenuineIntel");
        return FAILURE;
    }

    if (CPUID_VENDOR_EDX != edx) {
        BFALERT("cpu is vendor is not GenuineIntel");
        return FAILURE;
    }

    return 0;
}

/**
 * <!-- description -->
 *   @brief Check if the cpu supports needed VMX and XSAVE.
 *
 * <!-- inputs/outputs -->
 *   @return Returns 0 on success, FAILURE otherwise.
 */
static inline int64_t
check_cpuid_features(void)
{
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;

    eax = CPUID_LEAF_FEATURE;
    ecx = 0U;

    arch_cpuid(&eax, &ebx, &ecx, &edx);

    if ((ecx & CPUID_FEATURE_ECX_VMX) == 0U) {
        BFALERT("cpu does not support VT-x");
        return FAILURE;
    }

    if ((ecx & CPUID_FEATURE_ECX_XSAVE) == 0U) {
        BFALERT("cpu does not support XSAVE");
        return FAILURE;
    }

    return 0;
}

/**
 * <!-- description -->
 *   @brief Check that XSAVES is supported and that neither xcr0 nor
 *     ia32_xss msr allow bits 63:32 to be 1.
 *
 * <!-- inputs/outputs -->
 *   @return Return 0 on success, FAILURE otherwise.
 */
static inline int64_t
check_cpuid_xsave(void)
{
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;

    eax = CPUID_LEAF_XSAVE;
    ecx = 0;

    arch_cpuid(&eax, &ebx, &ecx, &edx);

    if (CPUID_XSAVE0_EDX_UPPER_XCR0 != edx) {
        BFALERT("cpu allows setting upper 32 bits in xcr0: 0x%x", edx);
        return FAILURE;
    }

    eax = CPUID_LEAF_XSAVE;
    ecx = 1;

    arch_cpuid(&eax, &ebx, &ecx, &edx);

    if ((eax & CPUID_XSAVE1_EAX_XSAVES) == 0U) {
        BFALERT("cpu does not support XSAVES/XRSTORS");
        return FAILURE;
    }

    if (CPUID_XSAVE1_EDX_UPPER_IA32_XSS != edx) {
        BFALERT("cpu allows setting upper 32 bits in ia32_xss: 0x%x", edx);
        return FAILURE;
    }

    return 0;
}

/**
 * <!-- description -->
 *   @brief Check that BIOS hasn't locked us out of VMX.
 *
 * <!-- inputs/outputs -->
 *   @return Return 0 if VMX is usable, FAILURE otherwise.
 */
static inline int64_t
check_msr_feature_ctrl(void)
{
    uint64_t msr = arch_rdmsr(MSR_IA32_FEATURE_CTRL);

    if ((msr & FEATURE_CTRL_LOCKED) != 0U) {
        if ((msr & FEATURE_CTRL_VMX_ENABLED_OUTSIDE_SMX) == 0U) {
            BFALERT("BIOS disabled VT-x");
            return FAILURE;
        }
    }

    return 0;
}

/**
 * <!-- description -->
 *   @brief Check that the VT-x implementation support the TRUE controls
 *
 * <!-- inputs/outputs -->
 *   @return Return 0 on success, FAILURE otherwise.
 */
static inline int64_t
check_msr_vmx_basic(void)
{
    uint64_t msr = arch_rdmsr(MSR_IA32_VMX_BASIC);

    if ((msr & VMX_BASIC_TRUE_CTRLS) == 0U) {
        BFALERT("VT-x implementation does not support true controls");
        return FAILURE;
    }

    return 0;
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
arch_check_hve_support(void)
{
    if (check_cpuid_vendor() != 0) {
        return FAILURE;
    }

    if (check_cpuid_features() != 0) {
        return FAILURE;
    }

    if (check_cpuid_xsave() != 0) {
        return FAILURE;
    }

    if (check_msr_feature_ctrl() != 0) {
        return FAILURE;
    }

    if (check_msr_vmx_basic() != 0) {
        return FAILURE;
    }

    return 0;
}
