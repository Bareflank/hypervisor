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

#define CPUID_MAXIMUM_STANDARD_FUNCTION_NUMBER_AND_VENDOR_STRING 0x0U

/// @class cpuid_result
///
/// <!-- description -->
///   @brief Defines the return registers associated with the CPUID
///     instruction.
///
struct cpuid_result
{
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
};

/// <!-- description -->
///   @brief Executes the CPUID instruction given the provided EAX and ECX
///     and returns the results in the cpuid_result structure.
///
/// <!-- inputs/outputs -->
///   @param eax the index used by the CPUID instruction
///   @param ecx the subindex used by the CPUID instruction
///   @param res a pointer to the structure to return the results of CPUID
///     to.
///
void arch_cpuid(uint32_t const eax, uint32_t const ecx, struct cpuid_result *res);

#endif
