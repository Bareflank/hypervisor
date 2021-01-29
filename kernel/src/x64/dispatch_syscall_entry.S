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

    swapgs

    mov gs:[0x110], rcx
    mov gs:[0x150], r11

    mov gs:[0x108], rbx
    mov gs:[0x120], rbp
    mov gs:[0x158], r12
    mov gs:[0x160], r13
    mov gs:[0x168], r14
    mov gs:[0x170], r15

    mov gs:[0x100], rax
    mov gs:[0x130], rdi
    mov gs:[0x128], rsi
    mov gs:[0x118], rdx
    mov gs:[0x148], r10
    mov gs:[0x138], r8
    mov gs:[0x140], r9

    mov gs:[0x180], rsp
    mov rsp, gs:[0x928]

    mov gs:[0x938], rsp
    mov rax, gs:[0x930]
    mov gs:[0x900], rax
    mov rax, gs:[0x938]
    mov gs:[0x908], rax

    mov rdi, gs:[0x800]
    call dispatch_syscall_trampoline

    mov rdx, gs:[0x920]
    mov gs:[0x900], rdx
    mov rdx, gs:[0x928]
    mov gs:[0x908], rdx

    mov rsp, gs:[0x180]

    mov r9,  gs:[0x140]
    mov r8,  gs:[0x138]
    mov r10, gs:[0x148]
    mov rdx, gs:[0x118]
    mov rsi, gs:[0x128]
    mov rdi, gs:[0x130]

    mov r15, gs:[0x170]
    mov r14, gs:[0x168]
    mov r13, gs:[0x160]
    mov r12, gs:[0x158]
    mov rbp, gs:[0x120]
    mov rbx, gs:[0x108]

    mov r11, gs:[0x150]
    mov rcx, gs:[0x110]

    swapgs

    .byte 0x48
    sysret

    .size dispatch_syscall_entry, .-dispatch_syscall_entry

    /**************************************************************************/
    /* Fast Fail Routine                                                      */
    /**************************************************************************/

    .globl  dispatch_syscall_fast_fail_entry
    .type   dispatch_syscall_fast_fail_entry, @function
dispatch_syscall_fast_fail_entry:

    mov rax, gs:[0x920]
    mov gs:[0x900], rax
    mov rax, gs:[0x928]
    mov gs:[0x908], rax

    mov rsp, gs:[0x180]

    mov r9,  gs:[0x140]
    mov r8,  gs:[0x138]
    mov r10, gs:[0x148]
    mov rdx, gs:[0x118]
    mov rsi, gs:[0x128]
    mov rdi, gs:[0x130]

    mov r15, gs:[0x170]
    mov r14, gs:[0x168]
    mov r13, gs:[0x160]
    mov r12, gs:[0x158]
    mov rbp, gs:[0x120]
    mov rbx, gs:[0x108]

    mov r11, gs:[0x150]
    mov rcx, gs:[0x110]

    swapgs

    mov rax, 0xDEAD000000010001
    .byte 0x48
    sysret

    .size dispatch_syscall_fast_fail_entry, .-dispatch_syscall_fast_fail_entry
