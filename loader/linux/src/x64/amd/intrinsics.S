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

     .code64
    .intel_syntax noprefix

    /// <!-- description -->
    ///   @brief Executes the CPUID instruction given the provided EAX and ECX
    ///     and returns the results.
    ///
    /// <!-- inputs/outputs -->
    ///   @param eax the index used by the CPUID instruction
    ///   @param ecx the subindex used by the CPUID instruction
    ///   @param res a pointer to the structure to return the results of CPUID
    ///     to.
    ///
    .globl  arch_cpuid
    .type   arch_cpuid, @function
arch_cpuid:
    push rbx

    mov r10, rdx
    mov r11, rcx

    mov eax, [rdi]
    mov ecx, [rdx]
    cpuid
    mov [rdi], eax
    mov [rsi], ebx
    mov [r10], ecx
    mov [r11], edx

    pop rbx
    ret



    /// <!-- description -->
    ///   @brief Executes the RDMSR instruction given the provided MSR
    ///     and returns the results
    ///
    /// <!-- inputs/outputs -->
    ///   @param ecx the MSR to read
    ///   @return Returns the resulting MSR value
    ///
    .globl  arch_rdmsr
    .type   arch_rdmsr, @function
arch_rdmsr:

    mov ecx, edi
    rdmsr
    shl rdx, 32
    or rax, rdx

    ret



    /// <!-- description -->
    ///   @brief Executes the WRMSR instruction given the provided MSR
    ///     and value
    ///
    /// <!-- inputs/outputs -->
    ///   @param ecx the MSR to write to the value
    ///   @param val the value to write to the given MSR
    ///
    .globl  arch_wrmsr
    .type   arch_wrmsr, @function
arch_wrmsr:

    mov rax, rsi
    mov rdx, rsi
    shr rdx, 32
    mov ecx, edi
    wrmsr

    ret
