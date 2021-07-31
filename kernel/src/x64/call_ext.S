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

    .globl  call_ext
    .type   call_ext, @function
call_ext:

    mov r10, rcx

    mov gs:[0x000], rbx
    mov gs:[0x008], rbp
    mov gs:[0x010], r12
    mov gs:[0x018], r13
    mov gs:[0x020], r14
    mov gs:[0x028], r15

    mov rax, gs:[0x238]
    mov fs:[0xFF0], rax
    mov rax, gs:[0x208]
    mov fs:[0xFF8], eax

    mov gs:[0x1A8], rsp
    mov rax, gs:[0x1A0]
    mov gs:[0x180], rax
    mov rax, gs:[0x1A8]
    mov gs:[0x188], rax

    mov rcx, rdi
    mov rsp, rsi
    mov r11, 0x2

    mov rdi, rdx
    mov rsi, r10

    xor rax, rax
    xor rbx, rbx
    xor rdx, rdx
    xor rbp, rbp
    xor r8, r8
    xor r9, r9
    xor r10, r10
    xor r12, r12
    xor r13, r13
    xor r14, r14
    xor r15, r15

    sysretq
    int 3

    .size call_ext, .-call_ext

    /**************************************************************************/
    /* Fast Fail Routine                                                      */
    /**************************************************************************/

    .globl  call_ext_fast_fail_entry
    .type   call_ext_fast_fail_entry, @function
call_ext_fast_fail_entry:

    mov rax, gs:[0x190]
    mov gs:[0x180], rax
    mov rax, gs:[0x198]
    mov gs:[0x188], rax

    mov r15, gs:[0x028]
    mov r14, gs:[0x020]
    mov r13, gs:[0x018]
    mov r12, gs:[0x010]
    mov rbp, gs:[0x008]
    mov rbx, gs:[0x000]

    mov rax, 0xFFFFFFFFFFFFFFFF
    ret
    int 3

    .size call_ext_fast_fail_entry, .-call_ext_fast_fail_entry
