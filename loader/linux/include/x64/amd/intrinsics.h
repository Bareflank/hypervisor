/* SPDX-License-Identifier: SPDX-License-Identifier: GPL-2.0 OR MIT */

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

#ifndef LOADER_INTRINSICS_H
#define LOADER_INTRINSICS_H

#include <loader_types.h>

/* -------------------------------------------------------------------------- */
/* - CPUID                                                                  - */
/* -------------------------------------------------------------------------- */

#define CPUID_FN0000_0000 0x00000000U
#define CPUID_FN0000_0000_EBX_VENDOR_ID (0x68747541U)
#define CPUID_FN0000_0000_ECX_VENDOR_ID (0x444d4163U)
#define CPUID_FN0000_0000_EDX_VENDOR_ID (0x69746e65U)

#define CPUID_FN8000_0001 0x80000001U
#define CPUID_FN8000_0001_ECX_SVM (1U << 2U)

/// <!-- description -->
///   @brief Executes the CPUID instruction given the provided EAX and ECX
///     and returns the results
///
/// <!-- inputs/outputs -->
///   @param eax the index used by CPUID, returns resulting eax
///   @param ebx returns resulting ebx
///   @param ecx the subindex used by CPUID, returns the resulting ecx
///   @param edx returns resulting edx
///     to.
///
void arch_cpuid(uint32_t *const eax, uint32_t *const ebx, uint32_t *const ecx, uint32_t *const edx);

/* -------------------------------------------------------------------------- */
/* - MSRS                                                                   - */
/* -------------------------------------------------------------------------- */

#define MSR_VM_CR (0xC0010114U)
#define MSR_VM_CR_SVMDIS ((uint64_t)1 << 4U)
#define MSR_VM_CR_LOCK ((uint64_t)1 << 3U)
#define MSR_VM_CR_DIS_A20M ((uint64_t)1 << 2U)
#define MSR_VM_CR_R_INIT ((uint64_t)1 << 1U)
#define MSR_VM_CR_DPD ((uint64_t)1 << 0U)

/// <!-- description -->
///   @brief Executes the RDMSR instruction given the provided MSR
///     and returns the results
///
/// <!-- inputs/outputs -->
///   @param ecx the MSR to read
///   @return Returns the resulting MSR value
///
uint64_t arch_rdmsr(uint32_t const ecx);

/// <!-- description -->
///   @brief Executes the WRMSR instruction given the provided MSR
///     and value
///
/// <!-- inputs/outputs -->
///   @param ecx the MSR to write to the value
///   @param val the value to write to the given MSR
///
void arch_wrmsr(uint32_t const ecx, uint64_t val);

#endif
