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

    .globl  intrinsic_vmrun
    .type   intrinsic_vmrun, @function
intrinsic_vmrun:

    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    mov r11, rdi    /* guest VMCB */
    mov r12, rsi    /* guest VMCB phys */
    mov r13, rdx    /* host VMCB */
    mov r14, rcx    /* host VMCB phys */
    mov r15, r8     /* missing registers */

    /**************************************************************************/
    /* Missing Registgers                                                     */
    /**************************************************************************/

    mov rax, [r15 + 0x010]
    mov cr8, rax

    mov rax, [r15 + 0x018]
    mov dr0, rax

    mov rax, [r15 + 0x020]
    mov dr1, rax

    mov rax, [r15 + 0x028]
    mov dr2, rax

    mov rax, [r15 + 0x030]
    mov dr3, rax

    xor ecx, ecx
    xgetbv
    mov [r15 + 0x0D8], eax
    mov [r15 + 0x0DC], edx
    mov eax, [r15 + 0x088]
    mov edx, [r15 + 0x08C]
    xsetbv

    /**************************************************************************/
    /* PAT                                                                    */
    /**************************************************************************/

    mov rax, [r11 + 0x0090]
    and rax, 0x00000001
    jnz skip_load_pat

    mov edi, 0x00000277
    call intrinsic_rdmsr_unsafe
    mov [r13 + 0x0668], rax
    mov rsi, [r11 + 0x0668]
    call intrinsic_wrmsr_unsafe

skip_load_pat:

    /**************************************************************************/
    /* General Purpose Register State                                         */
    /**************************************************************************/

    mov rax, fs:[0x800]
    mov [r11 + 0x05F8], rax

    push r15
    push r11
    push r12
    push r13
    push r14

    mov rbx, fs:[0x808]
    mov rcx, fs:[0x810]
    mov rdx, fs:[0x818]
    mov rbp, fs:[0x820]
    mov rsi, fs:[0x828]
    mov rdi, fs:[0x830]
    mov r8,  fs:[0x838]
    mov r9,  fs:[0x840]
    mov r10, fs:[0x848]
    mov r11, fs:[0x850]
    mov r12, fs:[0x858]
    mov r13, fs:[0x860]
    mov r14, fs:[0x868]
    mov r15, fs:[0x870]

    /**************************************************************************/
    /* Run                                                                    */
    /**************************************************************************/

    mov rax, [rsp]
    vmsave rax

    mov rax, [rsp + 0x010]
    vmload rax

    sti
    vmrun rax
    cli

    mov rax, [rsp + 0x010]
    vmsave rax

    mov rax, [rsp]
    vmload rax

    /**************************************************************************/
    /* General Purpose Register State                                         */
    /**************************************************************************/

    mov fs:[0x870], r15
    mov fs:[0x868], r14
    mov fs:[0x860], r13
    mov fs:[0x858], r12
    mov fs:[0x850], r11
    mov fs:[0x848], r10
    mov fs:[0x840], r9
    mov fs:[0x838], r8
    mov fs:[0x830], rdi
    mov fs:[0x828], rsi
    mov fs:[0x820], rbp
    mov fs:[0x818], rdx
    mov fs:[0x810], rcx
    mov fs:[0x808], rbx

    pop r14
    pop r13
    pop r12
    pop r11
    pop r15

    mov rax, [r11 + 0x05F8]
    mov fs:[0x800], rax

    /**************************************************************************/
    /* PAT                                                                    */
    /**************************************************************************/

    mov rax, [r11 + 0x0090]
    and rax, 0x00000001
    jnz skip_save_pat

    mov edi, 0x00000277
    call intrinsic_rdmsr_unsafe
    mov [r11 + 0x0668], rax
    mov rsi, [r13 + 0x0668]
    call intrinsic_wrmsr_unsafe

skip_save_pat:

    /**************************************************************************/
    /* Missing Registers                                                      */
    /**************************************************************************/

    xor ecx, ecx
    xgetbv
    mov [r15 + 0x088], eax
    mov [r15 + 0x08C], edx
    mov eax, [r15 + 0x0D8]
    mov edx, [r15 + 0x0DC]
    xsetbv

    xor rcx, rcx

    mov rax, dr3
    mov [r15 + 0x030], rax
    mov dr3, rcx

    mov rax, dr2
    mov [r15 + 0x028], rax
    mov dr2, rcx

    mov rax, dr1
    mov [r15 + 0x020], rax
    mov dr1, rcx

    mov rax, dr0
    mov [r15 + 0x018], rax
    mov dr0, rcx

    mov rax, cr8
    mov [r15 + 0x010], rax
    mov cr8, rcx

    mov cr2, rcx

    /**************************************************************************/
    /* Done                                                                   */
    /**************************************************************************/

    mov rax, [r11 + 0x0070]

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx

    ret
    int 3

    .size intrinsic_vmrun, .-intrinsic_vmrun
