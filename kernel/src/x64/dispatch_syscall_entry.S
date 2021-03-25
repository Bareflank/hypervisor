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

    .globl  dispatch_syscall_entry
    .type   dispatch_syscall_entry, @function
dispatch_syscall_entry:

    mov gs:[0x040], rcx
    mov gs:[0x080], r11

    mov gs:[0x038], rbx
    mov gs:[0x050], rbp
    mov gs:[0x088], r12
    mov gs:[0x090], r13
    mov gs:[0x098], r14
    mov gs:[0x0A0], r15

    mov gs:[0x030], rax
    mov gs:[0x060], rdi
    mov gs:[0x058], rsi
    mov gs:[0x048], rdx
    mov gs:[0x078], r10
    mov gs:[0x068], r8
    mov gs:[0x070], r9

    mov gs:[0x0A8], rsp
    mov rsp, gs:[0x1A8]

    mov gs:[0x1B8], rsp
    mov rax, gs:[0x1B0]
    mov gs:[0x180], rax
    mov rax, gs:[0x1B8]
    mov gs:[0x188], rax

    push 0x40002
    popf

    xor rax, rax
    mov gs:[0x280], rax
    mov rax, 0xDEAD000000010001
    mov gs:[0x288], rax

    mov rdi, gs:[0x200]
    call dispatch_syscall_trampoline

    cmp rax, 0x0
    jne dispatch_syscall_fast_fail_entry

    mov rdx, gs:[0x1A0]
    mov gs:[0x180], rdx
    mov rdx, gs:[0x1A8]
    mov gs:[0x188], rdx

    mov rsp, gs:[0x0A8]

    mov r9,  gs:[0x070]
    mov r8,  gs:[0x068]
    mov r10, gs:[0x078]
    mov rdx, gs:[0x048]
    mov rsi, gs:[0x058]
    mov rdi, gs:[0x060]
    mov rax, gs:[0x288]

    mov r15, gs:[0x0A0]
    mov r14, gs:[0x098]
    mov r13, gs:[0x090]
    mov r12, gs:[0x088]
    mov rbp, gs:[0x050]
    mov rbx, gs:[0x038]

    mov r11, gs:[0x080]
    mov rcx, gs:[0x040]

    sysretq
    int 3

    .size dispatch_syscall_entry, .-dispatch_syscall_entry

    /**************************************************************************/
    /* Fast Fail Routine                                                      */
    /**************************************************************************/

    .globl  dispatch_syscall_fast_fail_entry
    .type   dispatch_syscall_fast_fail_entry, @function
dispatch_syscall_fast_fail_entry:

    mov rax, gs:[0x1A0]
    mov gs:[0x180], rax
    mov rax, gs:[0x1A8]
    mov gs:[0x188], rax

    mov rdi, gs:[0x200]
    call dispatch_syscall_trampoline_failure

    mov rsp, gs:[0x0A8]

    mov r9,  gs:[0x070]
    mov r8,  gs:[0x068]
    mov r10, gs:[0x078]
    mov rdx, gs:[0x048]
    mov rsi, gs:[0x058]
    mov rdi, gs:[0x060]
    mov rax, gs:[0x288]

    mov r15, gs:[0x0A0]
    mov r14, gs:[0x098]
    mov r13, gs:[0x090]
    mov r12, gs:[0x088]
    mov rbp, gs:[0x050]
    mov rbx, gs:[0x038]

    mov r11, gs:[0x080]
    mov rcx, gs:[0x040]

    sysretq
    int 3

    .size dispatch_syscall_fast_fail_entry, .-dispatch_syscall_fast_fail_entry
