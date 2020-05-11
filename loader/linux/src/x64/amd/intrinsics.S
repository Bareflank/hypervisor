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
    ///     and returns the results in the cpuid_result structure.
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

    mov r11, rdx

    mov rax, rdi
    mov rcx, rsi
    cpuid

    mov [rdx + 0x00], rax
    mov [rdx + 0x08], rbx
    mov [rdx + 0x10], rcx
    mov [rdx + 0x18], rdx

    pop rbx
    ret
