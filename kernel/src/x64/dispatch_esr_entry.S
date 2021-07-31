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

    .globl  dispatch_esr_entry
    .type   dispatch_esr_entry, @function
dispatch_esr_entry:

    push 0x40002
    popf

    mov rdi, gs:[0x200]
    call dispatch_esr_trampoline

    cmp rax, 0x0
    jne return_to_current_fast_fail

    ret
    int 3

    .size dispatch_esr_entry, .-dispatch_esr_entry

    /**************************************************************************/
    /* ESR Routines                                                           */
    /**************************************************************************/

    .globl  dispatch_esr_entry_0
    .type   dispatch_esr_entry_0, @function
dispatch_esr_entry_0:

    mov gs:[0x0B0], rax
    mov gs:[0x0B8], rbx
    mov gs:[0x0C0], rcx
    mov gs:[0x0C8], rdx
    mov gs:[0x0D0], rbp
    mov gs:[0x0D8], rsi
    mov gs:[0x0E0], rdi
    mov gs:[0x0E8], r8
    mov gs:[0x0F0], r9
    mov gs:[0x0F8], r10
    mov gs:[0x100], r11
    mov gs:[0x108], r12
    mov gs:[0x110], r13
    mov gs:[0x118], r14
    mov gs:[0x120], r15

    mov rax, [rsp + 0x00]
    mov gs:[0x128], rax
    mov rax, [rsp + 0x18]
    mov gs:[0x130], rax

    mov rax, 0x0
    mov gs:[0x138], rax
    mov rax, 0x0
    mov gs:[0x140], rax

    mov rax, cr0
    mov gs:[0x148], rax
    mov rax, cr2
    mov gs:[0x150], rax
    mov rax, cr3
    mov gs:[0x158], rax
    mov rax, cr4
    mov gs:[0x160], rax

    mov rax, [rsp + 0x08]
    mov gs:[0x168], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x170], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x178], rax

    call dispatch_esr_entry

    mov r15, gs:[0x120]
    mov r14, gs:[0x118]
    mov r13, gs:[0x110]
    mov r12, gs:[0x108]
    mov r11, gs:[0x100]
    mov r10, gs:[0x0F8]
    mov r9,  gs:[0x0F0]
    mov r8,  gs:[0x0E8]
    mov rdi, gs:[0x0E0]
    mov rsi, gs:[0x0D8]
    mov rbp, gs:[0x0D0]
    mov rdx, gs:[0x0C8]
    mov rcx, gs:[0x0C0]
    mov rbx, gs:[0x0B8]
    mov rax, gs:[0x0B0]

    iretq
    int 3

    .size dispatch_esr_entry_0, .-dispatch_esr_entry_0



    .globl  dispatch_esr_entry_1
    .type   dispatch_esr_entry_1, @function
dispatch_esr_entry_1:

    mov gs:[0x0B0], rax
    mov gs:[0x0B8], rbx
    mov gs:[0x0C0], rcx
    mov gs:[0x0C8], rdx
    mov gs:[0x0D0], rbp
    mov gs:[0x0D8], rsi
    mov gs:[0x0E0], rdi
    mov gs:[0x0E8], r8
    mov gs:[0x0F0], r9
    mov gs:[0x0F8], r10
    mov gs:[0x100], r11
    mov gs:[0x108], r12
    mov gs:[0x110], r13
    mov gs:[0x118], r14
    mov gs:[0x120], r15

    mov rax, [rsp + 0x00]
    mov gs:[0x128], rax
    mov rax, [rsp + 0x18]
    mov gs:[0x130], rax

    mov rax, 0x1
    mov gs:[0x138], rax
    mov rax, 0x0
    mov gs:[0x140], rax

    mov rax, cr0
    mov gs:[0x148], rax
    mov rax, cr2
    mov gs:[0x150], rax
    mov rax, cr3
    mov gs:[0x158], rax
    mov rax, cr4
    mov gs:[0x160], rax

    mov rax, [rsp + 0x08]
    mov gs:[0x168], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x170], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x178], rax

    call dispatch_esr_entry

    mov r15, gs:[0x120]
    mov r14, gs:[0x118]
    mov r13, gs:[0x110]
    mov r12, gs:[0x108]
    mov r11, gs:[0x100]
    mov r10, gs:[0x0F8]
    mov r9,  gs:[0x0F0]
    mov r8,  gs:[0x0E8]
    mov rdi, gs:[0x0E0]
    mov rsi, gs:[0x0D8]
    mov rbp, gs:[0x0D0]
    mov rdx, gs:[0x0C8]
    mov rcx, gs:[0x0C0]
    mov rbx, gs:[0x0B8]
    mov rax, gs:[0x0B0]

    iretq
    int 3

    .size dispatch_esr_entry_1, .-dispatch_esr_entry_1



    .globl  dispatch_esr_entry_2
    .type   dispatch_esr_entry_2, @function
dispatch_esr_entry_2:

    mov gs:[0x0B0], rax
    mov gs:[0x0B8], rbx
    mov gs:[0x0C0], rcx
    mov gs:[0x0C8], rdx
    mov gs:[0x0D0], rbp
    mov gs:[0x0D8], rsi
    mov gs:[0x0E0], rdi
    mov gs:[0x0E8], r8
    mov gs:[0x0F0], r9
    mov gs:[0x0F8], r10
    mov gs:[0x100], r11
    mov gs:[0x108], r12
    mov gs:[0x110], r13
    mov gs:[0x118], r14
    mov gs:[0x120], r15

    mov rax, 0x2
    mov gs:[0x138], rax

    mov rdi, gs:[0x200]
    call dispatch_esr_trampoline

    mov r15, gs:[0x120]
    mov r14, gs:[0x118]
    mov r13, gs:[0x110]
    mov r12, gs:[0x108]
    mov r11, gs:[0x100]
    mov r10, gs:[0x0F8]
    mov r9,  gs:[0x0F0]
    mov r8,  gs:[0x0E8]
    mov rdi, gs:[0x0E0]
    mov rsi, gs:[0x0D8]
    mov rbp, gs:[0x0D0]
    mov rdx, gs:[0x0C8]
    mov rcx, gs:[0x0C0]
    mov rbx, gs:[0x0B8]
    mov rax, gs:[0x0B0]

    iretq
    int 3

    .size dispatch_esr_entry_2, .-dispatch_esr_entry_2



    .globl  dispatch_esr_entry_3
    .type   dispatch_esr_entry_3, @function
dispatch_esr_entry_3:

    jne return_to_current_fast_fail
    .size dispatch_esr_entry_3, .-dispatch_esr_entry_3



    .globl  dispatch_esr_entry_4
    .type   dispatch_esr_entry_4, @function
dispatch_esr_entry_4:

    mov gs:[0x0B0], rax
    mov gs:[0x0B8], rbx
    mov gs:[0x0C0], rcx
    mov gs:[0x0C8], rdx
    mov gs:[0x0D0], rbp
    mov gs:[0x0D8], rsi
    mov gs:[0x0E0], rdi
    mov gs:[0x0E8], r8
    mov gs:[0x0F0], r9
    mov gs:[0x0F8], r10
    mov gs:[0x100], r11
    mov gs:[0x108], r12
    mov gs:[0x110], r13
    mov gs:[0x118], r14
    mov gs:[0x120], r15

    mov rax, [rsp + 0x00]
    mov gs:[0x128], rax
    mov rax, [rsp + 0x18]
    mov gs:[0x130], rax

    mov rax, 0x4
    mov gs:[0x138], rax
    mov rax, 0x0
    mov gs:[0x140], rax

    mov rax, cr0
    mov gs:[0x148], rax
    mov rax, cr2
    mov gs:[0x150], rax
    mov rax, cr3
    mov gs:[0x158], rax
    mov rax, cr4
    mov gs:[0x160], rax

    mov rax, [rsp + 0x08]
    mov gs:[0x168], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x170], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x178], rax

    call dispatch_esr_entry

    mov r15, gs:[0x120]
    mov r14, gs:[0x118]
    mov r13, gs:[0x110]
    mov r12, gs:[0x108]
    mov r11, gs:[0x100]
    mov r10, gs:[0x0F8]
    mov r9,  gs:[0x0F0]
    mov r8,  gs:[0x0E8]
    mov rdi, gs:[0x0E0]
    mov rsi, gs:[0x0D8]
    mov rbp, gs:[0x0D0]
    mov rdx, gs:[0x0C8]
    mov rcx, gs:[0x0C0]
    mov rbx, gs:[0x0B8]
    mov rax, gs:[0x0B0]

    iretq
    int 3

    .size dispatch_esr_entry_4, .-dispatch_esr_entry_4



    .globl  dispatch_esr_entry_5
    .type   dispatch_esr_entry_5, @function
dispatch_esr_entry_5:

    mov gs:[0x0B0], rax
    mov gs:[0x0B8], rbx
    mov gs:[0x0C0], rcx
    mov gs:[0x0C8], rdx
    mov gs:[0x0D0], rbp
    mov gs:[0x0D8], rsi
    mov gs:[0x0E0], rdi
    mov gs:[0x0E8], r8
    mov gs:[0x0F0], r9
    mov gs:[0x0F8], r10
    mov gs:[0x100], r11
    mov gs:[0x108], r12
    mov gs:[0x110], r13
    mov gs:[0x118], r14
    mov gs:[0x120], r15

    mov rax, [rsp + 0x00]
    mov gs:[0x128], rax
    mov rax, [rsp + 0x18]
    mov gs:[0x130], rax

    mov rax, 0x5
    mov gs:[0x138], rax
    mov rax, 0x0
    mov gs:[0x140], rax

    mov rax, cr0
    mov gs:[0x148], rax
    mov rax, cr2
    mov gs:[0x150], rax
    mov rax, cr3
    mov gs:[0x158], rax
    mov rax, cr4
    mov gs:[0x160], rax

    mov rax, [rsp + 0x08]
    mov gs:[0x168], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x170], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x178], rax

    call dispatch_esr_entry

    mov r15, gs:[0x120]
    mov r14, gs:[0x118]
    mov r13, gs:[0x110]
    mov r12, gs:[0x108]
    mov r11, gs:[0x100]
    mov r10, gs:[0x0F8]
    mov r9,  gs:[0x0F0]
    mov r8,  gs:[0x0E8]
    mov rdi, gs:[0x0E0]
    mov rsi, gs:[0x0D8]
    mov rbp, gs:[0x0D0]
    mov rdx, gs:[0x0C8]
    mov rcx, gs:[0x0C0]
    mov rbx, gs:[0x0B8]
    mov rax, gs:[0x0B0]

    iretq
    int 3

    .size dispatch_esr_entry_5, .-dispatch_esr_entry_5



    .globl  dispatch_esr_entry_6
    .type   dispatch_esr_entry_6, @function
dispatch_esr_entry_6:

    mov gs:[0x0B0], rax
    mov gs:[0x0B8], rbx
    mov gs:[0x0C0], rcx
    mov gs:[0x0C8], rdx
    mov gs:[0x0D0], rbp
    mov gs:[0x0D8], rsi
    mov gs:[0x0E0], rdi
    mov gs:[0x0E8], r8
    mov gs:[0x0F0], r9
    mov gs:[0x0F8], r10
    mov gs:[0x100], r11
    mov gs:[0x108], r12
    mov gs:[0x110], r13
    mov gs:[0x118], r14
    mov gs:[0x120], r15

    mov rax, [rsp + 0x00]
    mov gs:[0x128], rax
    mov rax, [rsp + 0x18]
    mov gs:[0x130], rax

    mov rax, 0x6
    mov gs:[0x138], rax
    mov rax, 0x0
    mov gs:[0x140], rax

    mov rax, cr0
    mov gs:[0x148], rax
    mov rax, cr2
    mov gs:[0x150], rax
    mov rax, cr3
    mov gs:[0x158], rax
    mov rax, cr4
    mov gs:[0x160], rax

    mov rax, [rsp + 0x08]
    mov gs:[0x168], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x170], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x178], rax

    call dispatch_esr_entry

    mov r15, gs:[0x120]
    mov r14, gs:[0x118]
    mov r13, gs:[0x110]
    mov r12, gs:[0x108]
    mov r11, gs:[0x100]
    mov r10, gs:[0x0F8]
    mov r9,  gs:[0x0F0]
    mov r8,  gs:[0x0E8]
    mov rdi, gs:[0x0E0]
    mov rsi, gs:[0x0D8]
    mov rbp, gs:[0x0D0]
    mov rdx, gs:[0x0C8]
    mov rcx, gs:[0x0C0]
    mov rbx, gs:[0x0B8]
    mov rax, gs:[0x0B0]

    iretq
    int 3

    .size dispatch_esr_entry_6, .-dispatch_esr_entry_6



    .globl  dispatch_esr_entry_7
    .type   dispatch_esr_entry_7, @function
dispatch_esr_entry_7:

    mov gs:[0x0B0], rax
    mov gs:[0x0B8], rbx
    mov gs:[0x0C0], rcx
    mov gs:[0x0C8], rdx
    mov gs:[0x0D0], rbp
    mov gs:[0x0D8], rsi
    mov gs:[0x0E0], rdi
    mov gs:[0x0E8], r8
    mov gs:[0x0F0], r9
    mov gs:[0x0F8], r10
    mov gs:[0x100], r11
    mov gs:[0x108], r12
    mov gs:[0x110], r13
    mov gs:[0x118], r14
    mov gs:[0x120], r15

    mov rax, [rsp + 0x00]
    mov gs:[0x128], rax
    mov rax, [rsp + 0x18]
    mov gs:[0x130], rax

    mov rax, 0x7
    mov gs:[0x138], rax
    mov rax, 0x0
    mov gs:[0x140], rax

    mov rax, cr0
    mov gs:[0x148], rax
    mov rax, cr2
    mov gs:[0x150], rax
    mov rax, cr3
    mov gs:[0x158], rax
    mov rax, cr4
    mov gs:[0x160], rax

    mov rax, [rsp + 0x08]
    mov gs:[0x168], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x170], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x178], rax

    call dispatch_esr_entry

    mov r15, gs:[0x120]
    mov r14, gs:[0x118]
    mov r13, gs:[0x110]
    mov r12, gs:[0x108]
    mov r11, gs:[0x100]
    mov r10, gs:[0x0F8]
    mov r9,  gs:[0x0F0]
    mov r8,  gs:[0x0E8]
    mov rdi, gs:[0x0E0]
    mov rsi, gs:[0x0D8]
    mov rbp, gs:[0x0D0]
    mov rdx, gs:[0x0C8]
    mov rcx, gs:[0x0C0]
    mov rbx, gs:[0x0B8]
    mov rax, gs:[0x0B0]

    iretq
    int 3

    .size dispatch_esr_entry_7, .-dispatch_esr_entry_7



    .globl  dispatch_esr_entry_8
    .type   dispatch_esr_entry_8, @function
dispatch_esr_entry_8:

    mov gs:[0x0B0], rax
    mov gs:[0x0B8], rbx
    mov gs:[0x0C0], rcx
    mov gs:[0x0C8], rdx
    mov gs:[0x0D0], rbp
    mov gs:[0x0D8], rsi
    mov gs:[0x0E0], rdi
    mov gs:[0x0E8], r8
    mov gs:[0x0F0], r9
    mov gs:[0x0F8], r10
    mov gs:[0x100], r11
    mov gs:[0x108], r12
    mov gs:[0x110], r13
    mov gs:[0x118], r14
    mov gs:[0x120], r15

    mov rax, [rsp + 0x08]
    mov gs:[0x128], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x130], rax

    mov rax, 0x8
    mov gs:[0x138], rax
    mov rax, [rsp + 0x00]
    mov gs:[0x140], rax

    mov rax, cr0
    mov gs:[0x148], rax
    mov rax, cr2
    mov gs:[0x150], rax
    mov rax, cr3
    mov gs:[0x158], rax
    mov rax, cr4
    mov gs:[0x160], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x168], rax
    mov rax, [rsp + 0x28]
    mov gs:[0x170], rax

    mov rax, [rsp + 0x18]
    mov gs:[0x178], rax

    call dispatch_esr_entry

    pop rax

    mov r15, gs:[0x120]
    mov r14, gs:[0x118]
    mov r13, gs:[0x110]
    mov r12, gs:[0x108]
    mov r11, gs:[0x100]
    mov r10, gs:[0x0F8]
    mov r9,  gs:[0x0F0]
    mov r8,  gs:[0x0E8]
    mov rdi, gs:[0x0E0]
    mov rsi, gs:[0x0D8]
    mov rbp, gs:[0x0D0]
    mov rdx, gs:[0x0C8]
    mov rcx, gs:[0x0C0]
    mov rbx, gs:[0x0B8]
    mov rax, gs:[0x0B0]

    iretq
    int 3

    .size dispatch_esr_entry_8, .-dispatch_esr_entry_8



    .globl  dispatch_esr_entry_10
    .type   dispatch_esr_entry_10, @function
dispatch_esr_entry_10:

    mov gs:[0x0B0], rax
    mov gs:[0x0B8], rbx
    mov gs:[0x0C0], rcx
    mov gs:[0x0C8], rdx
    mov gs:[0x0D0], rbp
    mov gs:[0x0D8], rsi
    mov gs:[0x0E0], rdi
    mov gs:[0x0E8], r8
    mov gs:[0x0F0], r9
    mov gs:[0x0F8], r10
    mov gs:[0x100], r11
    mov gs:[0x108], r12
    mov gs:[0x110], r13
    mov gs:[0x118], r14
    mov gs:[0x120], r15

    mov rax, [rsp + 0x08]
    mov gs:[0x128], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x130], rax

    mov rax, 0xA
    mov gs:[0x138], rax
    mov rax, [rsp + 0x00]
    mov gs:[0x140], rax

    mov rax, cr0
    mov gs:[0x148], rax
    mov rax, cr2
    mov gs:[0x150], rax
    mov rax, cr3
    mov gs:[0x158], rax
    mov rax, cr4
    mov gs:[0x160], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x168], rax
    mov rax, [rsp + 0x28]
    mov gs:[0x170], rax

    mov rax, [rsp + 0x18]
    mov gs:[0x178], rax

    call dispatch_esr_entry

    pop rax

    mov r15, gs:[0x120]
    mov r14, gs:[0x118]
    mov r13, gs:[0x110]
    mov r12, gs:[0x108]
    mov r11, gs:[0x100]
    mov r10, gs:[0x0F8]
    mov r9,  gs:[0x0F0]
    mov r8,  gs:[0x0E8]
    mov rdi, gs:[0x0E0]
    mov rsi, gs:[0x0D8]
    mov rbp, gs:[0x0D0]
    mov rdx, gs:[0x0C8]
    mov rcx, gs:[0x0C0]
    mov rbx, gs:[0x0B8]
    mov rax, gs:[0x0B0]

    iretq
    int 3

    .size dispatch_esr_entry_10, .-dispatch_esr_entry_10



    .globl  dispatch_esr_entry_11
    .type   dispatch_esr_entry_11, @function
dispatch_esr_entry_11:

    mov gs:[0x0B0], rax
    mov gs:[0x0B8], rbx
    mov gs:[0x0C0], rcx
    mov gs:[0x0C8], rdx
    mov gs:[0x0D0], rbp
    mov gs:[0x0D8], rsi
    mov gs:[0x0E0], rdi
    mov gs:[0x0E8], r8
    mov gs:[0x0F0], r9
    mov gs:[0x0F8], r10
    mov gs:[0x100], r11
    mov gs:[0x108], r12
    mov gs:[0x110], r13
    mov gs:[0x118], r14
    mov gs:[0x120], r15

    mov rax, [rsp + 0x08]
    mov gs:[0x128], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x130], rax

    mov rax, 0xB
    mov gs:[0x138], rax
    mov rax, [rsp + 0x00]
    mov gs:[0x140], rax

    mov rax, cr0
    mov gs:[0x148], rax
    mov rax, cr2
    mov gs:[0x150], rax
    mov rax, cr3
    mov gs:[0x158], rax
    mov rax, cr4
    mov gs:[0x160], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x168], rax
    mov rax, [rsp + 0x28]
    mov gs:[0x170], rax

    mov rax, [rsp + 0x18]
    mov gs:[0x178], rax

    call dispatch_esr_entry

    pop rax

    mov r15, gs:[0x120]
    mov r14, gs:[0x118]
    mov r13, gs:[0x110]
    mov r12, gs:[0x108]
    mov r11, gs:[0x100]
    mov r10, gs:[0x0F8]
    mov r9,  gs:[0x0F0]
    mov r8,  gs:[0x0E8]
    mov rdi, gs:[0x0E0]
    mov rsi, gs:[0x0D8]
    mov rbp, gs:[0x0D0]
    mov rdx, gs:[0x0C8]
    mov rcx, gs:[0x0C0]
    mov rbx, gs:[0x0B8]
    mov rax, gs:[0x0B0]

    iretq
    int 3

    .size dispatch_esr_entry_11, .-dispatch_esr_entry_11



    .globl  dispatch_esr_entry_12
    .type   dispatch_esr_entry_12, @function
dispatch_esr_entry_12:

    mov gs:[0x0B0], rax
    mov gs:[0x0B8], rbx
    mov gs:[0x0C0], rcx
    mov gs:[0x0C8], rdx
    mov gs:[0x0D0], rbp
    mov gs:[0x0D8], rsi
    mov gs:[0x0E0], rdi
    mov gs:[0x0E8], r8
    mov gs:[0x0F0], r9
    mov gs:[0x0F8], r10
    mov gs:[0x100], r11
    mov gs:[0x108], r12
    mov gs:[0x110], r13
    mov gs:[0x118], r14
    mov gs:[0x120], r15

    mov rax, [rsp + 0x08]
    mov gs:[0x128], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x130], rax

    mov rax, 0xC
    mov gs:[0x138], rax
    mov rax, [rsp + 0x00]
    mov gs:[0x140], rax

    mov rax, cr0
    mov gs:[0x148], rax
    mov rax, cr2
    mov gs:[0x150], rax
    mov rax, cr3
    mov gs:[0x158], rax
    mov rax, cr4
    mov gs:[0x160], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x168], rax
    mov rax, [rsp + 0x28]
    mov gs:[0x170], rax

    mov rax, [rsp + 0x18]
    mov gs:[0x178], rax

    call dispatch_esr_entry

    pop rax

    mov r15, gs:[0x120]
    mov r14, gs:[0x118]
    mov r13, gs:[0x110]
    mov r12, gs:[0x108]
    mov r11, gs:[0x100]
    mov r10, gs:[0x0F8]
    mov r9,  gs:[0x0F0]
    mov r8,  gs:[0x0E8]
    mov rdi, gs:[0x0E0]
    mov rsi, gs:[0x0D8]
    mov rbp, gs:[0x0D0]
    mov rdx, gs:[0x0C8]
    mov rcx, gs:[0x0C0]
    mov rbx, gs:[0x0B8]
    mov rax, gs:[0x0B0]

    iretq
    int 3

    .size dispatch_esr_entry_12, .-dispatch_esr_entry_12



    .globl  dispatch_esr_entry_13
    .type   dispatch_esr_entry_13, @function
dispatch_esr_entry_13:

    mov gs:[0x0B0], rax
    mov gs:[0x0B8], rbx
    mov gs:[0x0C0], rcx
    mov gs:[0x0C8], rdx
    mov gs:[0x0D0], rbp
    mov gs:[0x0D8], rsi
    mov gs:[0x0E0], rdi
    mov gs:[0x0E8], r8
    mov gs:[0x0F0], r9
    mov gs:[0x0F8], r10
    mov gs:[0x100], r11
    mov gs:[0x108], r12
    mov gs:[0x110], r13
    mov gs:[0x118], r14
    mov gs:[0x120], r15

    mov rax, gs:[0x250]
    cmp rax, 0x0
    jne dispatch_esr_entry_13_fix_rip

    mov rax, [rsp + 0x08]
    mov gs:[0x128], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x130], rax

    mov rax, 0xD
    mov gs:[0x138], rax
    mov rax, [rsp + 0x00]
    mov gs:[0x140], rax

    mov rax, cr0
    mov gs:[0x148], rax
    mov rax, cr2
    mov gs:[0x150], rax
    mov rax, cr3
    mov gs:[0x158], rax
    mov rax, cr4
    mov gs:[0x160], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x168], rax
    mov rax, [rsp + 0x28]
    mov gs:[0x170], rax

    mov rax, [rsp + 0x18]
    mov gs:[0x178], rax

    call dispatch_esr_entry

dispatch_esr_entry_13_ret:

    pop rax

    mov r15, gs:[0x120]
    mov r14, gs:[0x118]
    mov r13, gs:[0x110]
    mov r12, gs:[0x108]
    mov r11, gs:[0x100]
    mov r10, gs:[0x0F8]
    mov r9,  gs:[0x0F0]
    mov r8,  gs:[0x0E8]
    mov rdi, gs:[0x0E0]
    mov rsi, gs:[0x0D8]
    mov rbp, gs:[0x0D0]
    mov rdx, gs:[0x0C8]
    mov rcx, gs:[0x0C0]
    mov rbx, gs:[0x0B8]
    mov rax, gs:[0x0B0]

    iretq
    int 3

dispatch_esr_entry_13_fix_rip:
    mov [rsp + 0x08], rax
    jmp dispatch_esr_entry_13_ret

    .size dispatch_esr_entry_13, .-dispatch_esr_entry_13



    .globl  dispatch_esr_entry_14
    .type   dispatch_esr_entry_14, @function
dispatch_esr_entry_14:

    mov gs:[0x0B0], rax
    mov gs:[0x0B8], rbx
    mov gs:[0x0C0], rcx
    mov gs:[0x0C8], rdx
    mov gs:[0x0D0], rbp
    mov gs:[0x0D8], rsi
    mov gs:[0x0E0], rdi
    mov gs:[0x0E8], r8
    mov gs:[0x0F0], r9
    mov gs:[0x0F8], r10
    mov gs:[0x100], r11
    mov gs:[0x108], r12
    mov gs:[0x110], r13
    mov gs:[0x118], r14
    mov gs:[0x120], r15

    mov rax, [rsp + 0x08]
    mov gs:[0x128], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x130], rax

    mov rax, 0xE
    mov gs:[0x138], rax
    mov rax, [rsp + 0x00]
    mov gs:[0x140], rax

    mov rax, cr0
    mov gs:[0x148], rax
    mov rax, cr2
    mov gs:[0x150], rax
    mov rax, cr3
    mov gs:[0x158], rax
    mov rax, cr4
    mov gs:[0x160], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x168], rax
    mov rax, [rsp + 0x28]
    mov gs:[0x170], rax

    mov rax, [rsp + 0x18]
    mov gs:[0x178], rax

    mov rax, 0x0
    mov cr2, rax

    call dispatch_esr_entry

    pop rax

    mov r15, gs:[0x120]
    mov r14, gs:[0x118]
    mov r13, gs:[0x110]
    mov r12, gs:[0x108]
    mov r11, gs:[0x100]
    mov r10, gs:[0x0F8]
    mov r9,  gs:[0x0F0]
    mov r8,  gs:[0x0E8]
    mov rdi, gs:[0x0E0]
    mov rsi, gs:[0x0D8]
    mov rbp, gs:[0x0D0]
    mov rdx, gs:[0x0C8]
    mov rcx, gs:[0x0C0]
    mov rbx, gs:[0x0B8]
    mov rax, gs:[0x0B0]

    iretq
    int 3

    .size dispatch_esr_entry_14, .-dispatch_esr_entry_14



    .globl  dispatch_esr_entry_16
    .type   dispatch_esr_entry_16, @function
dispatch_esr_entry_16:

    mov gs:[0x0B0], rax
    mov gs:[0x0B8], rbx
    mov gs:[0x0C0], rcx
    mov gs:[0x0C8], rdx
    mov gs:[0x0D0], rbp
    mov gs:[0x0D8], rsi
    mov gs:[0x0E0], rdi
    mov gs:[0x0E8], r8
    mov gs:[0x0F0], r9
    mov gs:[0x0F8], r10
    mov gs:[0x100], r11
    mov gs:[0x108], r12
    mov gs:[0x110], r13
    mov gs:[0x118], r14
    mov gs:[0x120], r15

    mov rax, [rsp + 0x00]
    mov gs:[0x128], rax
    mov rax, [rsp + 0x18]
    mov gs:[0x130], rax

    mov rax, 0x10
    mov gs:[0x138], rax
    mov rax, 0x0
    mov gs:[0x140], rax

    mov rax, cr0
    mov gs:[0x148], rax
    mov rax, cr2
    mov gs:[0x150], rax
    mov rax, cr3
    mov gs:[0x158], rax
    mov rax, cr4
    mov gs:[0x160], rax

    mov rax, [rsp + 0x08]
    mov gs:[0x168], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x170], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x178], rax

    call dispatch_esr_entry

    mov r15, gs:[0x120]
    mov r14, gs:[0x118]
    mov r13, gs:[0x110]
    mov r12, gs:[0x108]
    mov r11, gs:[0x100]
    mov r10, gs:[0x0F8]
    mov r9,  gs:[0x0F0]
    mov r8,  gs:[0x0E8]
    mov rdi, gs:[0x0E0]
    mov rsi, gs:[0x0D8]
    mov rbp, gs:[0x0D0]
    mov rdx, gs:[0x0C8]
    mov rcx, gs:[0x0C0]
    mov rbx, gs:[0x0B8]
    mov rax, gs:[0x0B0]

    iretq
    int 3

    .size dispatch_esr_entry_16, .-dispatch_esr_entry_16



    .globl  dispatch_esr_entry_17
    .type   dispatch_esr_entry_17, @function
dispatch_esr_entry_17:

    mov gs:[0x0B0], rax
    mov gs:[0x0B8], rbx
    mov gs:[0x0C0], rcx
    mov gs:[0x0C8], rdx
    mov gs:[0x0D0], rbp
    mov gs:[0x0D8], rsi
    mov gs:[0x0E0], rdi
    mov gs:[0x0E8], r8
    mov gs:[0x0F0], r9
    mov gs:[0x0F8], r10
    mov gs:[0x100], r11
    mov gs:[0x108], r12
    mov gs:[0x110], r13
    mov gs:[0x118], r14
    mov gs:[0x120], r15

    mov rax, [rsp + 0x08]
    mov gs:[0x128], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x130], rax

    mov rax, 0x11
    mov gs:[0x138], rax
    mov rax, [rsp + 0x00]
    mov gs:[0x140], rax

    mov rax, cr0
    mov gs:[0x148], rax
    mov rax, cr2
    mov gs:[0x150], rax
    mov rax, cr3
    mov gs:[0x158], rax
    mov rax, cr4
    mov gs:[0x160], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x168], rax
    mov rax, [rsp + 0x28]
    mov gs:[0x170], rax

    mov rax, [rsp + 0x18]
    mov gs:[0x178], rax

    call dispatch_esr_entry

    pop rax

    mov r15, gs:[0x120]
    mov r14, gs:[0x118]
    mov r13, gs:[0x110]
    mov r12, gs:[0x108]
    mov r11, gs:[0x100]
    mov r10, gs:[0x0F8]
    mov r9,  gs:[0x0F0]
    mov r8,  gs:[0x0E8]
    mov rdi, gs:[0x0E0]
    mov rsi, gs:[0x0D8]
    mov rbp, gs:[0x0D0]
    mov rdx, gs:[0x0C8]
    mov rcx, gs:[0x0C0]
    mov rbx, gs:[0x0B8]
    mov rax, gs:[0x0B0]

    iretq
    int 3

    .size dispatch_esr_entry_17, .-dispatch_esr_entry_17



    .globl  dispatch_esr_entry_18
    .type   dispatch_esr_entry_18, @function
dispatch_esr_entry_18:

    mov gs:[0x0B0], rax
    mov gs:[0x0B8], rbx
    mov gs:[0x0C0], rcx
    mov gs:[0x0C8], rdx
    mov gs:[0x0D0], rbp
    mov gs:[0x0D8], rsi
    mov gs:[0x0E0], rdi
    mov gs:[0x0E8], r8
    mov gs:[0x0F0], r9
    mov gs:[0x0F8], r10
    mov gs:[0x100], r11
    mov gs:[0x108], r12
    mov gs:[0x110], r13
    mov gs:[0x118], r14
    mov gs:[0x120], r15

    mov rax, [rsp + 0x00]
    mov gs:[0x128], rax
    mov rax, [rsp + 0x18]
    mov gs:[0x130], rax

    mov rax, 0x12
    mov gs:[0x138], rax
    mov rax, 0x0
    mov gs:[0x140], rax

    mov rax, cr0
    mov gs:[0x148], rax
    mov rax, cr2
    mov gs:[0x150], rax
    mov rax, cr3
    mov gs:[0x158], rax
    mov rax, cr4
    mov gs:[0x160], rax

    mov rax, [rsp + 0x08]
    mov gs:[0x168], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x170], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x178], rax

    call dispatch_esr_entry

    mov r15, gs:[0x120]
    mov r14, gs:[0x118]
    mov r13, gs:[0x110]
    mov r12, gs:[0x108]
    mov r11, gs:[0x100]
    mov r10, gs:[0x0F8]
    mov r9,  gs:[0x0F0]
    mov r8,  gs:[0x0E8]
    mov rdi, gs:[0x0E0]
    mov rsi, gs:[0x0D8]
    mov rbp, gs:[0x0D0]
    mov rdx, gs:[0x0C8]
    mov rcx, gs:[0x0C0]
    mov rbx, gs:[0x0B8]
    mov rax, gs:[0x0B0]

    iretq
    int 3

    .size dispatch_esr_entry_18, .-dispatch_esr_entry_18



    .globl  dispatch_esr_entry_19
    .type   dispatch_esr_entry_19, @function
dispatch_esr_entry_19:

    mov gs:[0x0B0], rax
    mov gs:[0x0B8], rbx
    mov gs:[0x0C0], rcx
    mov gs:[0x0C8], rdx
    mov gs:[0x0D0], rbp
    mov gs:[0x0D8], rsi
    mov gs:[0x0E0], rdi
    mov gs:[0x0E8], r8
    mov gs:[0x0F0], r9
    mov gs:[0x0F8], r10
    mov gs:[0x100], r11
    mov gs:[0x108], r12
    mov gs:[0x110], r13
    mov gs:[0x118], r14
    mov gs:[0x120], r15

    mov rax, [rsp + 0x00]
    mov gs:[0x128], rax
    mov rax, [rsp + 0x18]
    mov gs:[0x130], rax

    mov rax, 0x13
    mov gs:[0x138], rax
    mov rax, 0x0
    mov gs:[0x140], rax

    mov rax, cr0
    mov gs:[0x148], rax
    mov rax, cr2
    mov gs:[0x150], rax
    mov rax, cr3
    mov gs:[0x158], rax
    mov rax, cr4
    mov gs:[0x160], rax

    mov rax, [rsp + 0x08]
    mov gs:[0x168], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x170], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x178], rax

    call dispatch_esr_entry

    mov r15, gs:[0x120]
    mov r14, gs:[0x118]
    mov r13, gs:[0x110]
    mov r12, gs:[0x108]
    mov r11, gs:[0x100]
    mov r10, gs:[0x0F8]
    mov r9,  gs:[0x0F0]
    mov r8,  gs:[0x0E8]
    mov rdi, gs:[0x0E0]
    mov rsi, gs:[0x0D8]
    mov rbp, gs:[0x0D0]
    mov rdx, gs:[0x0C8]
    mov rcx, gs:[0x0C0]
    mov rbx, gs:[0x0B8]
    mov rax, gs:[0x0B0]

    iretq
    int 3

    .size dispatch_esr_entry_19, .-dispatch_esr_entry_19
