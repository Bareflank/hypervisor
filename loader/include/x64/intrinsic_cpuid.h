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

#ifndef INTRINSIC_CPUID_H
#define INTRINSIC_CPUID_H

#include <types.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * <!-- description -->
     *   @brief Executes the CPUID instruction given the provided EAX and ECX
     *     and returns the results
     *
     * <!-- inputs/outputs -->
     *   @param pmut_eax the index used by CPUID, returns resulting eax
     *   @param pmut_ebx returns resulting ebx
     *   @param pmut_ecx the subindex used by CPUID, returns the resulting ecx
     *   @param pmut_edx returns resulting edx to.
     */
    void intrinsic_cpuid(
        uint32_t *const pmut_eax,
        uint32_t *const pmut_ebx,
        uint32_t *const pmut_ecx,
        uint32_t *const pmut_edx) NOEXCEPT;

#ifdef __cplusplus
}
#endif

#endif
