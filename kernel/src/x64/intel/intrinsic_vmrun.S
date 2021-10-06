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

    mov r15, rdi    /* missing registers */

    /**************************************************************************/
    /* Missing Registgers                                                     */
    /**************************************************************************/

    mov rax, [r15 + 0x008]
    mov cr2, rax

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

    mov rax, [r15 + 0x038]
    mov dr6, rax

    xor ecx, ecx
    xgetbv
    mov [r15 + 0x0D8], eax
    mov [r15 + 0x0DC], edx
    mov eax, [r15 + 0x088]
    mov edx, [r15 + 0x08C]
    xsetbv

    /**************************************************************************/
    /* MSRs                                                                   */
    /**************************************************************************/

    mov edi, 0xC0000081
    mov rsi, [r15 + 0x060]
    call intrinsic_wrmsr_unsafe

    mov edi, 0xC0000082
    mov rsi, [r15 + 0x068]
    call intrinsic_wrmsr_unsafe

    mov edi, 0xC0000083
    mov rsi, [r15 + 0x070]
    call intrinsic_wrmsr_unsafe

    mov edi, 0xC0000084
    mov rsi, [r15 + 0x078]
    call intrinsic_wrmsr_unsafe

    mov edi, 0xC0000102
    mov rsi, [r15 + 0x080]
    call intrinsic_wrmsr_unsafe

    /**************************************************************************/
    /* NMIs                                                                   */
    /**************************************************************************/

    xor rax, rax
    mov gs:[0x258], rax

    mov rax, gs:[0x260]
    cmp rax, 0x1
    jne nmis_complete

    int 2

nmis_complete:

    /**************************************************************************/
    /* General Purpose Register State                                         */
    /**************************************************************************/

    push r15

    mov rax, 0x6C14
    vmwrite rax, rsp

    mov rax, [r15 + 0x000]
    cmp rax, 0x1

    mov rax, fs:[0x800]
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

    jne launch

resume:
    vmresume
    jmp intrinsic_vmexit
    int 3

launch:
    vmlaunch
    jmp intrinsic_vmexit
    int 3

    .size intrinsic_vmrun, .-intrinsic_vmrun



    .globl  intrinsic_vmexit
    .type   intrinsic_vmexit, @function
intrinsic_vmexit:

    push 0x40002
    popf

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
    mov fs:[0x800], rax

    pop r15

    /**************************************************************************/
    /* Signal VMLaunch/VMResume Success                                       */
    /**************************************************************************/

    mov rax, 0x1
    mov [r15 + 0x000], rax

    /**************************************************************************/
    /* NMIs                                                                   */
    /**************************************************************************/

    mov rax, 0x1
    mov gs:[0x258], rax

    /**************************************************************************/
    /* MSRs                                                                   */
    /**************************************************************************/

    mov edi, 0xC0000102
    call intrinsic_rdmsr_unsafe
    mov [r15 + 0x080], rax
    mov rsi, [r15 + 0x0D0]
    call intrinsic_wrmsr_unsafe

    mov edi, 0xC0000084
    call intrinsic_rdmsr_unsafe
    mov [r15 + 0x078], rax
    mov rsi, [r15 + 0x0C8]
    call intrinsic_wrmsr_unsafe

    mov edi, 0xC0000083
    call intrinsic_rdmsr_unsafe
    mov [r15 + 0x070], rax
    mov rsi, [r15 + 0x0C0]
    call intrinsic_wrmsr_unsafe

    mov edi, 0xC0000082
    call intrinsic_rdmsr_unsafe
    mov [r15 + 0x068], rax
    mov rsi, [r15 + 0x0B8]
    call intrinsic_wrmsr_unsafe

    mov edi, 0xC0000081
    call intrinsic_rdmsr_unsafe
    mov [r15 + 0x060], rax
    mov rsi, [r15 + 0x0B0]
    call intrinsic_wrmsr_unsafe

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

    mov rax, dr6
    mov [r15 + 0x038], rax
    mov dr6, rcx

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

    mov rax, cr2
    mov [r15 + 0x008], rax
    mov cr2, rcx

    /**************************************************************************/
    /* Done                                                                   */
    /**************************************************************************/

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx

    mov rax, 0x4402
    vmread rax, rax

    ret
    int 3

    .size intrinsic_vmrun, .-intrinsic_vmrun
