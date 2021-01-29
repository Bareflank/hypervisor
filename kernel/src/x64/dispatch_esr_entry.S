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

    mov rdi, gs:[0x800]
    call dispatch_esr_trampoline

    cmp rax, 0x0
    jne return_to_current_fast_fail

    ret
    .size dispatch_esr_entry, .-dispatch_esr_entry

    /**************************************************************************/
    /* ESR Routines                                                           */
    /**************************************************************************/

    .globl  dispatch_esr_entry_0
    .type   dispatch_esr_entry_0, @function
dispatch_esr_entry_0:

	cmp qword ptr [rsp + 0x08], 0x10
    je dispatch_esr_entry_0_skip_swapgs_prolog
	swapgs
dispatch_esr_entry_0_skip_swapgs_prolog:

    mov gs:[0x200], rax
    mov gs:[0x208], rbx
    mov gs:[0x210], rcx
    mov gs:[0x218], rdx
    mov gs:[0x220], rbp
    mov gs:[0x228], rsi
    mov gs:[0x230], rdi
    mov gs:[0x238], r8
    mov gs:[0x240], r9
    mov gs:[0x248], r10
    mov gs:[0x250], r11
    mov gs:[0x258], r12
    mov gs:[0x260], r13
    mov gs:[0x268], r14
    mov gs:[0x270], r15

    mov rax, [rsp + 0x00]
    mov gs:[0x278], rax
    mov rax, [rsp + 0x18]
    mov gs:[0x280], rax

    mov rax, 0x0
    mov gs:[0x288], rax
    mov rax, 0x0
    mov gs:[0x290], rax

    mov rax, cr0
    mov gs:[0x298], rax
    mov rax, cr2
    mov gs:[0x2A0], rax
    mov rax, cr3
    mov gs:[0x2A8], rax
    mov rax, cr4
    mov gs:[0x2B0], rax

    mov rax, [rsp + 0x08]
    mov gs:[0x2B8], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x2C0], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x2C8], rax

    call dispatch_esr_entry

    mov r15, gs:[0x270]
    mov r14, gs:[0x268]
    mov r13, gs:[0x260]
    mov r12, gs:[0x258]
    mov r11, gs:[0x250]
    mov r10, gs:[0x248]
    mov r9,  gs:[0x240]
    mov r8,  gs:[0x238]
    mov rdi, gs:[0x230]
    mov rsi, gs:[0x228]
    mov rbp, gs:[0x220]
    mov rdx, gs:[0x218]
    mov rcx, gs:[0x210]
    mov rbx, gs:[0x208]
    mov rax, gs:[0x200]

	cmp qword ptr [rsp + 0x08], 0x10
    je dispatch_esr_entry_0_skip_swapgs_epilog
	swapgs
dispatch_esr_entry_0_skip_swapgs_epilog:

    iretq
    .size dispatch_esr_entry_0, .-dispatch_esr_entry_0



    .globl  dispatch_esr_entry_1
    .type   dispatch_esr_entry_1, @function
dispatch_esr_entry_1:

	cmp qword ptr [rsp + 0x08], 0x10
    je dispatch_esr_entry_1_skip_swapgs_prolog
	swapgs
dispatch_esr_entry_1_skip_swapgs_prolog:

    mov gs:[0x200], rax
    mov gs:[0x208], rbx
    mov gs:[0x210], rcx
    mov gs:[0x218], rdx
    mov gs:[0x220], rbp
    mov gs:[0x228], rsi
    mov gs:[0x230], rdi
    mov gs:[0x238], r8
    mov gs:[0x240], r9
    mov gs:[0x248], r10
    mov gs:[0x250], r11
    mov gs:[0x258], r12
    mov gs:[0x260], r13
    mov gs:[0x268], r14
    mov gs:[0x270], r15

    mov rax, [rsp + 0x00]
    mov gs:[0x278], rax
    mov rax, [rsp + 0x18]
    mov gs:[0x280], rax

    mov rax, 0x1
    mov gs:[0x288], rax
    mov rax, 0x0
    mov gs:[0x290], rax

    mov rax, cr0
    mov gs:[0x298], rax
    mov rax, cr2
    mov gs:[0x2A0], rax
    mov rax, cr3
    mov gs:[0x2A8], rax
    mov rax, cr4
    mov gs:[0x2B0], rax

    mov rax, [rsp + 0x08]
    mov gs:[0x2B8], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x2C0], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x2C8], rax

    call dispatch_esr_entry

    mov r15, gs:[0x270]
    mov r14, gs:[0x268]
    mov r13, gs:[0x260]
    mov r12, gs:[0x258]
    mov r11, gs:[0x250]
    mov r10, gs:[0x248]
    mov r9,  gs:[0x240]
    mov r8,  gs:[0x238]
    mov rdi, gs:[0x230]
    mov rsi, gs:[0x228]
    mov rbp, gs:[0x220]
    mov rdx, gs:[0x218]
    mov rcx, gs:[0x210]
    mov rbx, gs:[0x208]
    mov rax, gs:[0x200]

	cmp qword ptr [rsp + 0x08], 0x10
    je dispatch_esr_entry_1_skip_swapgs_epilog
	swapgs
dispatch_esr_entry_1_skip_swapgs_epilog:

    iretq
    .size dispatch_esr_entry_1, .-dispatch_esr_entry_1



    .globl  dispatch_esr_entry_2
    .type   dispatch_esr_entry_2, @function
dispatch_esr_entry_2:

	cmp qword ptr [rsp + 0x08], 0x10
    je dispatch_esr_entry_2_skip_swapgs_prolog
	swapgs
dispatch_esr_entry_2_skip_swapgs_prolog:

    mov gs:[0x200], rax
    mov gs:[0x208], rbx
    mov gs:[0x210], rcx
    mov gs:[0x218], rdx
    mov gs:[0x220], rbp
    mov gs:[0x228], rsi
    mov gs:[0x230], rdi
    mov gs:[0x238], r8
    mov gs:[0x240], r9
    mov gs:[0x248], r10
    mov gs:[0x250], r11
    mov gs:[0x258], r12
    mov gs:[0x260], r13
    mov gs:[0x268], r14
    mov gs:[0x270], r15

    mov rax, 0x2
    mov gs:[0x288], rax

    mov rdi, gs:[0x800]
    call dispatch_esr_trampoline

    mov r15, gs:[0x270]
    mov r14, gs:[0x268]
    mov r13, gs:[0x260]
    mov r12, gs:[0x258]
    mov r11, gs:[0x250]
    mov r10, gs:[0x248]
    mov r9,  gs:[0x240]
    mov r8,  gs:[0x238]
    mov rdi, gs:[0x230]
    mov rsi, gs:[0x228]
    mov rbp, gs:[0x220]
    mov rdx, gs:[0x218]
    mov rcx, gs:[0x210]
    mov rbx, gs:[0x208]
    mov rax, gs:[0x200]

	cmp qword ptr [rsp + 0x08], 0x10
    je dispatch_esr_entry_2_skip_swapgs_epilog
	swapgs
dispatch_esr_entry_2_skip_swapgs_epilog:

    iretq
    .size dispatch_esr_entry_2, .-dispatch_esr_entry_2



    .globl  dispatch_esr_entry_3
    .type   dispatch_esr_entry_3, @function
dispatch_esr_entry_3:

	cmp qword ptr [rsp + 0x08], 0x10
    je dispatch_esr_entry_3_skip_swapgs_prolog
	swapgs
dispatch_esr_entry_3_skip_swapgs_prolog:

    mov gs:[0x200], rax
    mov gs:[0x208], rbx
    mov gs:[0x210], rcx
    mov gs:[0x218], rdx
    mov gs:[0x220], rbp
    mov gs:[0x228], rsi
    mov gs:[0x230], rdi
    mov gs:[0x238], r8
    mov gs:[0x240], r9
    mov gs:[0x248], r10
    mov gs:[0x250], r11
    mov gs:[0x258], r12
    mov gs:[0x260], r13
    mov gs:[0x268], r14
    mov gs:[0x270], r15

    mov rax, [rsp + 0x00]
    mov gs:[0x278], rax
    mov rax, [rsp + 0x18]
    mov gs:[0x280], rax

    mov rax, 0x3
    mov gs:[0x288], rax
    mov rax, 0x0
    mov gs:[0x290], rax

    mov rax, cr0
    mov gs:[0x298], rax
    mov rax, cr2
    mov gs:[0x2A0], rax
    mov rax, cr3
    mov gs:[0x2A8], rax
    mov rax, cr4
    mov gs:[0x2B0], rax

    mov rax, [rsp + 0x08]
    mov gs:[0x2B8], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x2C0], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x2C8], rax

    call dispatch_esr_entry

    mov r15, gs:[0x270]
    mov r14, gs:[0x268]
    mov r13, gs:[0x260]
    mov r12, gs:[0x258]
    mov r11, gs:[0x250]
    mov r10, gs:[0x248]
    mov r9,  gs:[0x240]
    mov r8,  gs:[0x238]
    mov rdi, gs:[0x230]
    mov rsi, gs:[0x228]
    mov rbp, gs:[0x220]
    mov rdx, gs:[0x218]
    mov rcx, gs:[0x210]
    mov rbx, gs:[0x208]
    mov rax, gs:[0x200]

	cmp qword ptr [rsp + 0x08], 0x10
    je dispatch_esr_entry_3_skip_swapgs_epilog
	swapgs
dispatch_esr_entry_3_skip_swapgs_epilog:

    iretq
    .size dispatch_esr_entry_3, .-dispatch_esr_entry_3



    .globl  dispatch_esr_entry_4
    .type   dispatch_esr_entry_4, @function
dispatch_esr_entry_4:

	cmp qword ptr [rsp + 0x08], 0x10
    je dispatch_esr_entry_4_skip_swapgs_prolog
	swapgs
dispatch_esr_entry_4_skip_swapgs_prolog:

    mov gs:[0x200], rax
    mov gs:[0x208], rbx
    mov gs:[0x210], rcx
    mov gs:[0x218], rdx
    mov gs:[0x220], rbp
    mov gs:[0x228], rsi
    mov gs:[0x230], rdi
    mov gs:[0x238], r8
    mov gs:[0x240], r9
    mov gs:[0x248], r10
    mov gs:[0x250], r11
    mov gs:[0x258], r12
    mov gs:[0x260], r13
    mov gs:[0x268], r14
    mov gs:[0x270], r15

    mov rax, [rsp + 0x00]
    mov gs:[0x278], rax
    mov rax, [rsp + 0x18]
    mov gs:[0x280], rax

    mov rax, 0x4
    mov gs:[0x288], rax
    mov rax, 0x0
    mov gs:[0x290], rax

    mov rax, cr0
    mov gs:[0x298], rax
    mov rax, cr2
    mov gs:[0x2A0], rax
    mov rax, cr3
    mov gs:[0x2A8], rax
    mov rax, cr4
    mov gs:[0x2B0], rax

    mov rax, [rsp + 0x08]
    mov gs:[0x2B8], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x2C0], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x2C8], rax

    call dispatch_esr_entry

    mov r15, gs:[0x270]
    mov r14, gs:[0x268]
    mov r13, gs:[0x260]
    mov r12, gs:[0x258]
    mov r11, gs:[0x250]
    mov r10, gs:[0x248]
    mov r9,  gs:[0x240]
    mov r8,  gs:[0x238]
    mov rdi, gs:[0x230]
    mov rsi, gs:[0x228]
    mov rbp, gs:[0x220]
    mov rdx, gs:[0x218]
    mov rcx, gs:[0x210]
    mov rbx, gs:[0x208]
    mov rax, gs:[0x200]

	cmp qword ptr [rsp + 0x08], 0x10
    je dispatch_esr_entry_4_skip_swapgs_epilog
	swapgs
dispatch_esr_entry_4_skip_swapgs_epilog:

    iretq
    .size dispatch_esr_entry_4, .-dispatch_esr_entry_4



    .globl  dispatch_esr_entry_5
    .type   dispatch_esr_entry_5, @function
dispatch_esr_entry_5:

	cmp qword ptr [rsp + 0x08], 0x10
    je dispatch_esr_entry_5_skip_swapgs_prolog
	swapgs
dispatch_esr_entry_5_skip_swapgs_prolog:

    mov gs:[0x200], rax
    mov gs:[0x208], rbx
    mov gs:[0x210], rcx
    mov gs:[0x218], rdx
    mov gs:[0x220], rbp
    mov gs:[0x228], rsi
    mov gs:[0x230], rdi
    mov gs:[0x238], r8
    mov gs:[0x240], r9
    mov gs:[0x248], r10
    mov gs:[0x250], r11
    mov gs:[0x258], r12
    mov gs:[0x260], r13
    mov gs:[0x268], r14
    mov gs:[0x270], r15

    mov rax, [rsp + 0x00]
    mov gs:[0x278], rax
    mov rax, [rsp + 0x18]
    mov gs:[0x280], rax

    mov rax, 0x5
    mov gs:[0x288], rax
    mov rax, 0x0
    mov gs:[0x290], rax

    mov rax, cr0
    mov gs:[0x298], rax
    mov rax, cr2
    mov gs:[0x2A0], rax
    mov rax, cr3
    mov gs:[0x2A8], rax
    mov rax, cr4
    mov gs:[0x2B0], rax

    mov rax, [rsp + 0x08]
    mov gs:[0x2B8], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x2C0], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x2C8], rax

    call dispatch_esr_entry

    mov r15, gs:[0x270]
    mov r14, gs:[0x268]
    mov r13, gs:[0x260]
    mov r12, gs:[0x258]
    mov r11, gs:[0x250]
    mov r10, gs:[0x248]
    mov r9,  gs:[0x240]
    mov r8,  gs:[0x238]
    mov rdi, gs:[0x230]
    mov rsi, gs:[0x228]
    mov rbp, gs:[0x220]
    mov rdx, gs:[0x218]
    mov rcx, gs:[0x210]
    mov rbx, gs:[0x208]
    mov rax, gs:[0x200]

	cmp qword ptr [rsp + 0x08], 0x10
    je dispatch_esr_entry_5_skip_swapgs_epilog
	swapgs
dispatch_esr_entry_5_skip_swapgs_epilog:

    iretq
    .size dispatch_esr_entry_5, .-dispatch_esr_entry_5



    .globl  dispatch_esr_entry_6
    .type   dispatch_esr_entry_6, @function
dispatch_esr_entry_6:

	cmp qword ptr [rsp + 0x08], 0x10
    je dispatch_esr_entry_6_skip_swapgs_prolog
	swapgs
dispatch_esr_entry_6_skip_swapgs_prolog:

    mov gs:[0x200], rax
    mov gs:[0x208], rbx
    mov gs:[0x210], rcx
    mov gs:[0x218], rdx
    mov gs:[0x220], rbp
    mov gs:[0x228], rsi
    mov gs:[0x230], rdi
    mov gs:[0x238], r8
    mov gs:[0x240], r9
    mov gs:[0x248], r10
    mov gs:[0x250], r11
    mov gs:[0x258], r12
    mov gs:[0x260], r13
    mov gs:[0x268], r14
    mov gs:[0x270], r15

    mov rax, [rsp + 0x00]
    mov gs:[0x278], rax
    mov rax, [rsp + 0x18]
    mov gs:[0x280], rax

    mov rax, 0x6
    mov gs:[0x288], rax
    mov rax, 0x0
    mov gs:[0x290], rax

    mov rax, cr0
    mov gs:[0x298], rax
    mov rax, cr2
    mov gs:[0x2A0], rax
    mov rax, cr3
    mov gs:[0x2A8], rax
    mov rax, cr4
    mov gs:[0x2B0], rax

    mov rax, [rsp + 0x08]
    mov gs:[0x2B8], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x2C0], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x2C8], rax

    call dispatch_esr_entry

    mov r15, gs:[0x270]
    mov r14, gs:[0x268]
    mov r13, gs:[0x260]
    mov r12, gs:[0x258]
    mov r11, gs:[0x250]
    mov r10, gs:[0x248]
    mov r9,  gs:[0x240]
    mov r8,  gs:[0x238]
    mov rdi, gs:[0x230]
    mov rsi, gs:[0x228]
    mov rbp, gs:[0x220]
    mov rdx, gs:[0x218]
    mov rcx, gs:[0x210]
    mov rbx, gs:[0x208]
    mov rax, gs:[0x200]

	cmp qword ptr [rsp + 0x08], 0x10
    je dispatch_esr_entry_6_skip_swapgs_epilog
	swapgs
dispatch_esr_entry_6_skip_swapgs_epilog:

    iretq
    .size dispatch_esr_entry_6, .-dispatch_esr_entry_6



    .globl  dispatch_esr_entry_7
    .type   dispatch_esr_entry_7, @function
dispatch_esr_entry_7:

	cmp qword ptr [rsp + 0x08], 0x10
    je dispatch_esr_entry_7_skip_swapgs_prolog
	swapgs
dispatch_esr_entry_7_skip_swapgs_prolog:

    mov gs:[0x200], rax
    mov gs:[0x208], rbx
    mov gs:[0x210], rcx
    mov gs:[0x218], rdx
    mov gs:[0x220], rbp
    mov gs:[0x228], rsi
    mov gs:[0x230], rdi
    mov gs:[0x238], r8
    mov gs:[0x240], r9
    mov gs:[0x248], r10
    mov gs:[0x250], r11
    mov gs:[0x258], r12
    mov gs:[0x260], r13
    mov gs:[0x268], r14
    mov gs:[0x270], r15

    mov rax, [rsp + 0x00]
    mov gs:[0x278], rax
    mov rax, [rsp + 0x18]
    mov gs:[0x280], rax

    mov rax, 0x7
    mov gs:[0x288], rax
    mov rax, 0x0
    mov gs:[0x290], rax

    mov rax, cr0
    mov gs:[0x298], rax
    mov rax, cr2
    mov gs:[0x2A0], rax
    mov rax, cr3
    mov gs:[0x2A8], rax
    mov rax, cr4
    mov gs:[0x2B0], rax

    mov rax, [rsp + 0x08]
    mov gs:[0x2B8], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x2C0], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x2C8], rax

    call dispatch_esr_entry

    mov r15, gs:[0x270]
    mov r14, gs:[0x268]
    mov r13, gs:[0x260]
    mov r12, gs:[0x258]
    mov r11, gs:[0x250]
    mov r10, gs:[0x248]
    mov r9,  gs:[0x240]
    mov r8,  gs:[0x238]
    mov rdi, gs:[0x230]
    mov rsi, gs:[0x228]
    mov rbp, gs:[0x220]
    mov rdx, gs:[0x218]
    mov rcx, gs:[0x210]
    mov rbx, gs:[0x208]
    mov rax, gs:[0x200]

	cmp qword ptr [rsp + 0x08], 0x10
    je dispatch_esr_entry_7_skip_swapgs_epilog
	swapgs
dispatch_esr_entry_7_skip_swapgs_epilog:

    iretq
    .size dispatch_esr_entry_7, .-dispatch_esr_entry_7



    .globl  dispatch_esr_entry_8
    .type   dispatch_esr_entry_8, @function
dispatch_esr_entry_8:

	cmp qword ptr [rsp + 0x10], 0x10
    je dispatch_esr_entry_8_skip_swapgs_prolog
	swapgs
dispatch_esr_entry_8_skip_swapgs_prolog:

    mov gs:[0x200], rax
    mov gs:[0x208], rbx
    mov gs:[0x210], rcx
    mov gs:[0x218], rdx
    mov gs:[0x220], rbp
    mov gs:[0x228], rsi
    mov gs:[0x230], rdi
    mov gs:[0x238], r8
    mov gs:[0x240], r9
    mov gs:[0x248], r10
    mov gs:[0x250], r11
    mov gs:[0x258], r12
    mov gs:[0x260], r13
    mov gs:[0x268], r14
    mov gs:[0x270], r15

    mov rax, [rsp + 0x08]
    mov gs:[0x278], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x280], rax

    mov rax, 0x8
    mov gs:[0x288], rax
    mov rax, [rsp + 0x00]
    mov gs:[0x290], rax

    mov rax, cr0
    mov gs:[0x298], rax
    mov rax, cr2
    mov gs:[0x2A0], rax
    mov rax, cr3
    mov gs:[0x2A8], rax
    mov rax, cr4
    mov gs:[0x2B0], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x2B8], rax
    mov rax, [rsp + 0x28]
    mov gs:[0x2C0], rax

    mov rax, [rsp + 0x18]
    mov gs:[0x2C8], rax

    call dispatch_esr_entry

    pop rax

    mov r15, gs:[0x270]
    mov r14, gs:[0x268]
    mov r13, gs:[0x260]
    mov r12, gs:[0x258]
    mov r11, gs:[0x250]
    mov r10, gs:[0x248]
    mov r9,  gs:[0x240]
    mov r8,  gs:[0x238]
    mov rdi, gs:[0x230]
    mov rsi, gs:[0x228]
    mov rbp, gs:[0x220]
    mov rdx, gs:[0x218]
    mov rcx, gs:[0x210]
    mov rbx, gs:[0x208]
    mov rax, gs:[0x200]

	cmp qword ptr [rsp + 0x10], 0x10
    je dispatch_esr_entry_8_skip_swapgs_epilog
	swapgs
dispatch_esr_entry_8_skip_swapgs_epilog:

    iretq
    .size dispatch_esr_entry_8, .-dispatch_esr_entry_8



    .globl  dispatch_esr_entry_10
    .type   dispatch_esr_entry_10, @function
dispatch_esr_entry_10:

	cmp qword ptr [rsp + 0x10], 0x10
    je dispatch_esr_entry_10_skip_swapgs_prolog
	swapgs
dispatch_esr_entry_10_skip_swapgs_prolog:

    mov gs:[0x200], rax
    mov gs:[0x208], rbx
    mov gs:[0x210], rcx
    mov gs:[0x218], rdx
    mov gs:[0x220], rbp
    mov gs:[0x228], rsi
    mov gs:[0x230], rdi
    mov gs:[0x238], r8
    mov gs:[0x240], r9
    mov gs:[0x248], r10
    mov gs:[0x250], r11
    mov gs:[0x258], r12
    mov gs:[0x260], r13
    mov gs:[0x268], r14
    mov gs:[0x270], r15

    mov rax, [rsp + 0x08]
    mov gs:[0x278], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x280], rax

    mov rax, 0xA
    mov gs:[0x288], rax
    mov rax, [rsp + 0x00]
    mov gs:[0x290], rax

    mov rax, cr0
    mov gs:[0x298], rax
    mov rax, cr2
    mov gs:[0x2A0], rax
    mov rax, cr3
    mov gs:[0x2A8], rax
    mov rax, cr4
    mov gs:[0x2B0], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x2B8], rax
    mov rax, [rsp + 0x28]
    mov gs:[0x2C0], rax

    mov rax, [rsp + 0x18]
    mov gs:[0x2C8], rax

    call dispatch_esr_entry

    pop rax

    mov r15, gs:[0x270]
    mov r14, gs:[0x268]
    mov r13, gs:[0x260]
    mov r12, gs:[0x258]
    mov r11, gs:[0x250]
    mov r10, gs:[0x248]
    mov r9,  gs:[0x240]
    mov r8,  gs:[0x238]
    mov rdi, gs:[0x230]
    mov rsi, gs:[0x228]
    mov rbp, gs:[0x220]
    mov rdx, gs:[0x218]
    mov rcx, gs:[0x210]
    mov rbx, gs:[0x208]
    mov rax, gs:[0x200]

	cmp qword ptr [rsp + 0x10], 0x10
    je dispatch_esr_entry_10_skip_swapgs_epilog
	swapgs
dispatch_esr_entry_10_skip_swapgs_epilog:

    iretq
    .size dispatch_esr_entry_10, .-dispatch_esr_entry_10



    .globl  dispatch_esr_entry_11
    .type   dispatch_esr_entry_11, @function
dispatch_esr_entry_11:

	cmp qword ptr [rsp + 0x10], 0x10
    je dispatch_esr_entry_11_skip_swapgs_prolog
	swapgs
dispatch_esr_entry_11_skip_swapgs_prolog:

    mov gs:[0x200], rax
    mov gs:[0x208], rbx
    mov gs:[0x210], rcx
    mov gs:[0x218], rdx
    mov gs:[0x220], rbp
    mov gs:[0x228], rsi
    mov gs:[0x230], rdi
    mov gs:[0x238], r8
    mov gs:[0x240], r9
    mov gs:[0x248], r10
    mov gs:[0x250], r11
    mov gs:[0x258], r12
    mov gs:[0x260], r13
    mov gs:[0x268], r14
    mov gs:[0x270], r15

    mov rax, [rsp + 0x08]
    mov gs:[0x278], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x280], rax

    mov rax, 0xB
    mov gs:[0x288], rax
    mov rax, [rsp + 0x00]
    mov gs:[0x290], rax

    mov rax, cr0
    mov gs:[0x298], rax
    mov rax, cr2
    mov gs:[0x2A0], rax
    mov rax, cr3
    mov gs:[0x2A8], rax
    mov rax, cr4
    mov gs:[0x2B0], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x2B8], rax
    mov rax, [rsp + 0x28]
    mov gs:[0x2C0], rax

    mov rax, [rsp + 0x18]
    mov gs:[0x2C8], rax

    call dispatch_esr_entry

    pop rax

    mov r15, gs:[0x270]
    mov r14, gs:[0x268]
    mov r13, gs:[0x260]
    mov r12, gs:[0x258]
    mov r11, gs:[0x250]
    mov r10, gs:[0x248]
    mov r9,  gs:[0x240]
    mov r8,  gs:[0x238]
    mov rdi, gs:[0x230]
    mov rsi, gs:[0x228]
    mov rbp, gs:[0x220]
    mov rdx, gs:[0x218]
    mov rcx, gs:[0x210]
    mov rbx, gs:[0x208]
    mov rax, gs:[0x200]

	cmp qword ptr [rsp + 0x10], 0x10
    je dispatch_esr_entry_11_skip_swapgs_epilog
	swapgs
dispatch_esr_entry_11_skip_swapgs_epilog:

    iretq
    .size dispatch_esr_entry_11, .-dispatch_esr_entry_11



    .globl  dispatch_esr_entry_12
    .type   dispatch_esr_entry_12, @function
dispatch_esr_entry_12:

	cmp qword ptr [rsp + 0x10], 0x10
    je dispatch_esr_entry_12_skip_swapgs_prolog
	swapgs
dispatch_esr_entry_12_skip_swapgs_prolog:

    mov gs:[0x200], rax
    mov gs:[0x208], rbx
    mov gs:[0x210], rcx
    mov gs:[0x218], rdx
    mov gs:[0x220], rbp
    mov gs:[0x228], rsi
    mov gs:[0x230], rdi
    mov gs:[0x238], r8
    mov gs:[0x240], r9
    mov gs:[0x248], r10
    mov gs:[0x250], r11
    mov gs:[0x258], r12
    mov gs:[0x260], r13
    mov gs:[0x268], r14
    mov gs:[0x270], r15

    mov rax, [rsp + 0x08]
    mov gs:[0x278], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x280], rax

    mov rax, 0xC
    mov gs:[0x288], rax
    mov rax, [rsp + 0x00]
    mov gs:[0x290], rax

    mov rax, cr0
    mov gs:[0x298], rax
    mov rax, cr2
    mov gs:[0x2A0], rax
    mov rax, cr3
    mov gs:[0x2A8], rax
    mov rax, cr4
    mov gs:[0x2B0], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x2B8], rax
    mov rax, [rsp + 0x28]
    mov gs:[0x2C0], rax

    mov rax, [rsp + 0x18]
    mov gs:[0x2C8], rax

    call dispatch_esr_entry

    pop rax

    mov r15, gs:[0x270]
    mov r14, gs:[0x268]
    mov r13, gs:[0x260]
    mov r12, gs:[0x258]
    mov r11, gs:[0x250]
    mov r10, gs:[0x248]
    mov r9,  gs:[0x240]
    mov r8,  gs:[0x238]
    mov rdi, gs:[0x230]
    mov rsi, gs:[0x228]
    mov rbp, gs:[0x220]
    mov rdx, gs:[0x218]
    mov rcx, gs:[0x210]
    mov rbx, gs:[0x208]
    mov rax, gs:[0x200]

	cmp qword ptr [rsp + 0x10], 0x10
    je dispatch_esr_entry_12_skip_swapgs_epilog
	swapgs
dispatch_esr_entry_12_skip_swapgs_epilog:

    iretq
    .size dispatch_esr_entry_12, .-dispatch_esr_entry_12



    .globl  dispatch_esr_entry_13
    .type   dispatch_esr_entry_13, @function
dispatch_esr_entry_13:

	cmp qword ptr [rsp + 0x10], 0x10
    je dispatch_esr_entry_13_skip_swapgs_prolog
	swapgs
dispatch_esr_entry_13_skip_swapgs_prolog:

    mov gs:[0x200], rax
    mov gs:[0x208], rbx
    mov gs:[0x210], rcx
    mov gs:[0x218], rdx
    mov gs:[0x220], rbp
    mov gs:[0x228], rsi
    mov gs:[0x230], rdi
    mov gs:[0x238], r8
    mov gs:[0x240], r9
    mov gs:[0x248], r10
    mov gs:[0x250], r11
    mov gs:[0x258], r12
    mov gs:[0x260], r13
    mov gs:[0x268], r14
    mov gs:[0x270], r15

    mov rax, gs:[0x850]
    cmp rax, 0x0
    jne dispatch_esr_entry_13_fix_rip

    mov rax, [rsp + 0x08]
    mov gs:[0x278], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x280], rax

    mov rax, 0xD
    mov gs:[0x288], rax
    mov rax, [rsp + 0x00]
    mov gs:[0x290], rax

    mov rax, cr0
    mov gs:[0x298], rax
    mov rax, cr2
    mov gs:[0x2A0], rax
    mov rax, cr3
    mov gs:[0x2A8], rax
    mov rax, cr4
    mov gs:[0x2B0], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x2B8], rax
    mov rax, [rsp + 0x28]
    mov gs:[0x2C0], rax

    mov rax, [rsp + 0x18]
    mov gs:[0x2C8], rax

    call dispatch_esr_entry

dispatch_esr_entry_13_ret:

    pop rax

    mov r15, gs:[0x270]
    mov r14, gs:[0x268]
    mov r13, gs:[0x260]
    mov r12, gs:[0x258]
    mov r11, gs:[0x250]
    mov r10, gs:[0x248]
    mov r9,  gs:[0x240]
    mov r8,  gs:[0x238]
    mov rdi, gs:[0x230]
    mov rsi, gs:[0x228]
    mov rbp, gs:[0x220]
    mov rdx, gs:[0x218]
    mov rcx, gs:[0x210]
    mov rbx, gs:[0x208]
    mov rax, gs:[0x200]

	cmp qword ptr [rsp + 0x10], 0x10
    je dispatch_esr_entry_13_skip_swapgs_epilog
	swapgs
dispatch_esr_entry_13_skip_swapgs_epilog:

    iretq

dispatch_esr_entry_13_fix_rip:
    mov [rsp + 0x08], rax
    jmp dispatch_esr_entry_13_ret

    .size dispatch_esr_entry_13, .-dispatch_esr_entry_13



    .globl  dispatch_esr_entry_14
    .type   dispatch_esr_entry_14, @function
dispatch_esr_entry_14:

	cmp qword ptr [rsp + 0x10], 0x10
    je dispatch_esr_entry_14_skip_swapgs_prolog
	swapgs
dispatch_esr_entry_14_skip_swapgs_prolog:

    mov gs:[0x200], rax
    mov gs:[0x208], rbx
    mov gs:[0x210], rcx
    mov gs:[0x218], rdx
    mov gs:[0x220], rbp
    mov gs:[0x228], rsi
    mov gs:[0x230], rdi
    mov gs:[0x238], r8
    mov gs:[0x240], r9
    mov gs:[0x248], r10
    mov gs:[0x250], r11
    mov gs:[0x258], r12
    mov gs:[0x260], r13
    mov gs:[0x268], r14
    mov gs:[0x270], r15

    mov rax, [rsp + 0x08]
    mov gs:[0x278], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x280], rax

    mov rax, 0xE
    mov gs:[0x288], rax
    mov rax, [rsp + 0x00]
    mov gs:[0x290], rax

    mov rax, cr0
    mov gs:[0x298], rax
    mov rax, cr2
    mov gs:[0x2A0], rax
    mov rax, cr3
    mov gs:[0x2A8], rax
    mov rax, cr4
    mov gs:[0x2B0], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x2B8], rax
    mov rax, [rsp + 0x28]
    mov gs:[0x2C0], rax

    mov rax, [rsp + 0x18]
    mov gs:[0x2C8], rax

    mov rax, 0x0
    mov cr2, rax

    call dispatch_esr_entry

    pop rax

    mov r15, gs:[0x270]
    mov r14, gs:[0x268]
    mov r13, gs:[0x260]
    mov r12, gs:[0x258]
    mov r11, gs:[0x250]
    mov r10, gs:[0x248]
    mov r9,  gs:[0x240]
    mov r8,  gs:[0x238]
    mov rdi, gs:[0x230]
    mov rsi, gs:[0x228]
    mov rbp, gs:[0x220]
    mov rdx, gs:[0x218]
    mov rcx, gs:[0x210]
    mov rbx, gs:[0x208]
    mov rax, gs:[0x200]

	cmp qword ptr [rsp + 0x10], 0x10
    je dispatch_esr_entry_14_skip_swapgs_epilog
	swapgs
dispatch_esr_entry_14_skip_swapgs_epilog:

    iretq
    .size dispatch_esr_entry_14, .-dispatch_esr_entry_14



    .globl  dispatch_esr_entry_16
    .type   dispatch_esr_entry_16, @function
dispatch_esr_entry_16:

	cmp qword ptr [rsp + 0x08], 0x10
    je dispatch_esr_entry_16_skip_swapgs_prolog
	swapgs
dispatch_esr_entry_16_skip_swapgs_prolog:

    mov gs:[0x200], rax
    mov gs:[0x208], rbx
    mov gs:[0x210], rcx
    mov gs:[0x218], rdx
    mov gs:[0x220], rbp
    mov gs:[0x228], rsi
    mov gs:[0x230], rdi
    mov gs:[0x238], r8
    mov gs:[0x240], r9
    mov gs:[0x248], r10
    mov gs:[0x250], r11
    mov gs:[0x258], r12
    mov gs:[0x260], r13
    mov gs:[0x268], r14
    mov gs:[0x270], r15

    mov rax, [rsp + 0x00]
    mov gs:[0x278], rax
    mov rax, [rsp + 0x18]
    mov gs:[0x280], rax

    mov rax, 0x10
    mov gs:[0x288], rax
    mov rax, 0x0
    mov gs:[0x290], rax

    mov rax, cr0
    mov gs:[0x298], rax
    mov rax, cr2
    mov gs:[0x2A0], rax
    mov rax, cr3
    mov gs:[0x2A8], rax
    mov rax, cr4
    mov gs:[0x2B0], rax

    mov rax, [rsp + 0x08]
    mov gs:[0x2B8], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x2C0], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x2C8], rax

    call dispatch_esr_entry

    mov r15, gs:[0x270]
    mov r14, gs:[0x268]
    mov r13, gs:[0x260]
    mov r12, gs:[0x258]
    mov r11, gs:[0x250]
    mov r10, gs:[0x248]
    mov r9,  gs:[0x240]
    mov r8,  gs:[0x238]
    mov rdi, gs:[0x230]
    mov rsi, gs:[0x228]
    mov rbp, gs:[0x220]
    mov rdx, gs:[0x218]
    mov rcx, gs:[0x210]
    mov rbx, gs:[0x208]
    mov rax, gs:[0x200]

	cmp qword ptr [rsp + 0x08], 0x10
    je dispatch_esr_entry_16_skip_swapgs_epilog
	swapgs
dispatch_esr_entry_16_skip_swapgs_epilog:

    iretq
    .size dispatch_esr_entry_16, .-dispatch_esr_entry_16



    .globl  dispatch_esr_entry_17
    .type   dispatch_esr_entry_17, @function
dispatch_esr_entry_17:

	cmp qword ptr [rsp + 0x10], 0x10
    je dispatch_esr_entry_17_skip_swapgs_prolog
	swapgs
dispatch_esr_entry_17_skip_swapgs_prolog:

    mov gs:[0x200], rax
    mov gs:[0x208], rbx
    mov gs:[0x210], rcx
    mov gs:[0x218], rdx
    mov gs:[0x220], rbp
    mov gs:[0x228], rsi
    mov gs:[0x230], rdi
    mov gs:[0x238], r8
    mov gs:[0x240], r9
    mov gs:[0x248], r10
    mov gs:[0x250], r11
    mov gs:[0x258], r12
    mov gs:[0x260], r13
    mov gs:[0x268], r14
    mov gs:[0x270], r15

    mov rax, [rsp + 0x08]
    mov gs:[0x278], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x280], rax

    mov rax, 0x11
    mov gs:[0x288], rax
    mov rax, [rsp + 0x00]
    mov gs:[0x290], rax

    mov rax, cr0
    mov gs:[0x298], rax
    mov rax, cr2
    mov gs:[0x2A0], rax
    mov rax, cr3
    mov gs:[0x2A8], rax
    mov rax, cr4
    mov gs:[0x2B0], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x2B8], rax
    mov rax, [rsp + 0x28]
    mov gs:[0x2C0], rax

    mov rax, [rsp + 0x18]
    mov gs:[0x2C8], rax

    call dispatch_esr_entry

    pop rax

    mov r15, gs:[0x270]
    mov r14, gs:[0x268]
    mov r13, gs:[0x260]
    mov r12, gs:[0x258]
    mov r11, gs:[0x250]
    mov r10, gs:[0x248]
    mov r9,  gs:[0x240]
    mov r8,  gs:[0x238]
    mov rdi, gs:[0x230]
    mov rsi, gs:[0x228]
    mov rbp, gs:[0x220]
    mov rdx, gs:[0x218]
    mov rcx, gs:[0x210]
    mov rbx, gs:[0x208]
    mov rax, gs:[0x200]

	cmp qword ptr [rsp + 0x10], 0x10
    je dispatch_esr_entry_17_skip_swapgs_epilog
	swapgs
dispatch_esr_entry_17_skip_swapgs_epilog:

    iretq
    .size dispatch_esr_entry_17, .-dispatch_esr_entry_17



    .globl  dispatch_esr_entry_18
    .type   dispatch_esr_entry_18, @function
dispatch_esr_entry_18:

	cmp qword ptr [rsp + 0x08], 0x10
    je dispatch_esr_entry_18_skip_swapgs_prolog
	swapgs
dispatch_esr_entry_18_skip_swapgs_prolog:

    mov gs:[0x200], rax
    mov gs:[0x208], rbx
    mov gs:[0x210], rcx
    mov gs:[0x218], rdx
    mov gs:[0x220], rbp
    mov gs:[0x228], rsi
    mov gs:[0x230], rdi
    mov gs:[0x238], r8
    mov gs:[0x240], r9
    mov gs:[0x248], r10
    mov gs:[0x250], r11
    mov gs:[0x258], r12
    mov gs:[0x260], r13
    mov gs:[0x268], r14
    mov gs:[0x270], r15

    mov rax, [rsp + 0x00]
    mov gs:[0x278], rax
    mov rax, [rsp + 0x18]
    mov gs:[0x280], rax

    mov rax, 0x12
    mov gs:[0x288], rax
    mov rax, 0x0
    mov gs:[0x290], rax

    mov rax, cr0
    mov gs:[0x298], rax
    mov rax, cr2
    mov gs:[0x2A0], rax
    mov rax, cr3
    mov gs:[0x2A8], rax
    mov rax, cr4
    mov gs:[0x2B0], rax

    mov rax, [rsp + 0x08]
    mov gs:[0x2B8], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x2C0], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x2C8], rax

    call dispatch_esr_entry

    mov r15, gs:[0x270]
    mov r14, gs:[0x268]
    mov r13, gs:[0x260]
    mov r12, gs:[0x258]
    mov r11, gs:[0x250]
    mov r10, gs:[0x248]
    mov r9,  gs:[0x240]
    mov r8,  gs:[0x238]
    mov rdi, gs:[0x230]
    mov rsi, gs:[0x228]
    mov rbp, gs:[0x220]
    mov rdx, gs:[0x218]
    mov rcx, gs:[0x210]
    mov rbx, gs:[0x208]
    mov rax, gs:[0x200]

	cmp qword ptr [rsp + 0x08], 0x10
    je dispatch_esr_entry_18_skip_swapgs_epilog
	swapgs
dispatch_esr_entry_18_skip_swapgs_epilog:

    iretq
    .size dispatch_esr_entry_18, .-dispatch_esr_entry_18



    .globl  dispatch_esr_entry_19
    .type   dispatch_esr_entry_19, @function
dispatch_esr_entry_19:

	cmp qword ptr [rsp + 0x08], 0x10
    je dispatch_esr_entry_19_skip_swapgs_prolog
	swapgs
dispatch_esr_entry_19_skip_swapgs_prolog:

    mov gs:[0x200], rax
    mov gs:[0x208], rbx
    mov gs:[0x210], rcx
    mov gs:[0x218], rdx
    mov gs:[0x220], rbp
    mov gs:[0x228], rsi
    mov gs:[0x230], rdi
    mov gs:[0x238], r8
    mov gs:[0x240], r9
    mov gs:[0x248], r10
    mov gs:[0x250], r11
    mov gs:[0x258], r12
    mov gs:[0x260], r13
    mov gs:[0x268], r14
    mov gs:[0x270], r15

    mov rax, [rsp + 0x00]
    mov gs:[0x278], rax
    mov rax, [rsp + 0x18]
    mov gs:[0x280], rax

    mov rax, 0x13
    mov gs:[0x288], rax
    mov rax, 0x0
    mov gs:[0x290], rax

    mov rax, cr0
    mov gs:[0x298], rax
    mov rax, cr2
    mov gs:[0x2A0], rax
    mov rax, cr3
    mov gs:[0x2A8], rax
    mov rax, cr4
    mov gs:[0x2B0], rax

    mov rax, [rsp + 0x08]
    mov gs:[0x2B8], rax
    mov rax, [rsp + 0x20]
    mov gs:[0x2C0], rax

    mov rax, [rsp + 0x10]
    mov gs:[0x2C8], rax

    call dispatch_esr_entry

    mov r15, gs:[0x270]
    mov r14, gs:[0x268]
    mov r13, gs:[0x260]
    mov r12, gs:[0x258]
    mov r11, gs:[0x250]
    mov r10, gs:[0x248]
    mov r9,  gs:[0x240]
    mov r8,  gs:[0x238]
    mov rdi, gs:[0x230]
    mov rsi, gs:[0x228]
    mov rbp, gs:[0x220]
    mov rdx, gs:[0x218]
    mov rcx, gs:[0x210]
    mov rbx, gs:[0x208]
    mov rax, gs:[0x200]

	cmp qword ptr [rsp + 0x08], 0x10
    je dispatch_esr_entry_19_skip_swapgs_epilog
	swapgs
dispatch_esr_entry_19_skip_swapgs_epilog:

    iretq
    .size dispatch_esr_entry_19, .-dispatch_esr_entry_19
