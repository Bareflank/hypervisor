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

    .globl  intrinsic_invlpg
    .type   intrinsic_invlpg, @function
intrinsic_invlpg:

    invlpg [rdi]

    ret
    int 3

    .size intrinsic_invlpg, .-intrinsic_invlpg



    .globl  intrinsic_es_selector
    .type   intrinsic_es_selector, @function
intrinsic_es_selector:

    xor rax, rax
    mov ax, es

    ret
    int 3

    .size intrinsic_es_selector, .-intrinsic_es_selector



    .globl  intrinsic_cs_selector
    .type   intrinsic_cs_selector, @function
intrinsic_cs_selector:

    xor rax, rax
    mov ax, cs

    ret
    int 3

    .size intrinsic_cs_selector, .-intrinsic_cs_selector



    .globl  intrinsic_ss_selector
    .type   intrinsic_ss_selector, @function
intrinsic_ss_selector:

    xor rax, rax
    mov ax, ss

    ret
    int 3

    .size intrinsic_ss_selector, .-intrinsic_ss_selector



    .globl  intrinsic_ds_selector
    .type   intrinsic_ds_selector, @function
intrinsic_ds_selector:

    xor rax, rax
    mov ax, ds

    ret
    int 3

    .size intrinsic_ds_selector, .-intrinsic_ds_selector



    .globl  intrinsic_fs_selector
    .type   intrinsic_fs_selector, @function
intrinsic_fs_selector:

    xor rax, rax
    mov ax, fs

    ret
    int 3

    .size intrinsic_fs_selector, .-intrinsic_fs_selector



    .globl  intrinsic_gs_selector
    .type   intrinsic_gs_selector, @function
intrinsic_gs_selector:

    xor rax, rax
    mov ax, gs

    ret
    int 3

    .size intrinsic_gs_selector, .-intrinsic_gs_selector



    .globl  intrinsic_tr_selector
    .type   intrinsic_tr_selector, @function
intrinsic_tr_selector:

    xor rax, rax
    str ax

    ret
    int 3

    .size intrinsic_tr_selector, .-intrinsic_tr_selector



    .globl  intrinsic_cr0
    .type   intrinsic_cr0, @function
intrinsic_cr0:

    mov rax, cr0

    ret
    int 3

    .size intrinsic_cr0, .-intrinsic_cr0



    .globl  intrinsic_cr3
    .type   intrinsic_cr3, @function
intrinsic_cr3:

    mov rax, cr3

    ret
    int 3

    .size intrinsic_cr3, .-intrinsic_cr3



    .globl  intrinsic_set_cr3
    .type   intrinsic_set_cr3, @function
intrinsic_set_cr3:

    mov cr3, rdi

    ret
    int 3

    .size intrinsic_set_cr3, .-intrinsic_set_cr3



    .globl  intrinsic_cr4
    .type   intrinsic_cr4, @function
intrinsic_cr4:

    mov rax, cr4

    ret
    int 3

    .size intrinsic_cr4, .-intrinsic_cr4



    .globl  intrinsic_tp
    .type   intrinsic_tp, @function
intrinsic_tp:

    mov ecx, 0xC0000100
    xor rax, rax
    rdmsr
    shl rdx, 32
    or rax, rdx

    ret
    int 3

    .size intrinsic_tp, .-intrinsic_tp



    .globl  intrinsic_set_tp
    .type   intrinsic_set_tp, @function
intrinsic_set_tp:

    mov rax, rdi
    mov rdx, rdi
    shr rdx, 32
    mov ecx, 0xC0000100
    wrmsr

    ret
    int 3

    .size intrinsic_set_tp, .-intrinsic_set_tp



    .globl  intrinsic_tls_reg
    .type   intrinsic_tls_reg, @function
intrinsic_tls_reg:

    mov rax, fs:[rdi]

    ret
    int 3

    .size intrinsic_tls_reg, .-intrinsic_tls_reg



    .globl  intrinsic_set_tls_reg
    .type   intrinsic_set_tls_reg, @function
intrinsic_set_tls_reg:

    mov fs:[rdi], rsi

    ret
    int 3

    .size intrinsic_set_tls_reg, .-intrinsic_set_tls_reg



    .globl  intrinsic_assert
    .type   intrinsic_assert, @function
intrinsic_assert:

    int 3

    .size intrinsic_assert, .-intrinsic_assert



    .globl  intrinsic_halt
    .type   intrinsic_halt, @function
intrinsic_halt:

    call msg_halt

    cli
    hlt

    .size intrinsic_halt, .-intrinsic_halt



    .globl  intrinsic_rdmsr
    .type   intrinsic_rdmsr, @function
intrinsic_rdmsr:

    lea rax, [rip + intrinsic_rdmsr_failed]
    mov gs:[0x250], rax

    mov ecx, edi
    xor rax, rax
    xor rdx, rdx
    rdmsr

    shl rdx, 32
    or rax, rdx
    mov [rsi], rax

    xor rax, rax
    mov gs:[0x250], rax

    ret
    int 3

intrinsic_rdmsr_failed:

    xor rax, rax
    mov gs:[0x250], rax

    mov rax, 0x1
    ret
    int 3

    .size intrinsic_rdmsr, .-intrinsic_rdmsr



    .globl  intrinsic_rdmsr_unsafe
    .type   intrinsic_rdmsr_unsafe, @function
intrinsic_rdmsr_unsafe:

    mov ecx, edi
    xor rax, rax
    xor rdx, rdx
    rdmsr
    shl rdx, 32
    or rax, rdx

    ret
    int 3

    .size intrinsic_rdmsr_unsafe, .-intrinsic_rdmsr_unsafe



    .globl  intrinsic_wrmsr
    .type   intrinsic_wrmsr, @function
intrinsic_wrmsr:

    lea rax, [rip + intrinsic_wrmsr_failed]
    mov gs:[0x250], rax

    mov ecx, edi
    mov rax, rsi
    mov rdx, rsi
    shr rdx, 32
    wrmsr

    xor rax, rax
    mov gs:[0x250], rax

    ret
    int 3

intrinsic_wrmsr_failed:

    xor rax, rax
    mov gs:[0x250], rax

    mov rax, 0x1
    ret
    int 3

    .size intrinsic_wrmsr, .-intrinsic_wrmsr



    .globl  intrinsic_wrmsr_unsafe
    .type   intrinsic_wrmsr_unsafe, @function
intrinsic_wrmsr_unsafe:

    mov ecx, edi
    mov rax, rsi
    mov rdx, rsi
    shr rdx, 32
    wrmsr

    ret
    int 3

    .size intrinsic_wrmsr_unsafe, .-intrinsic_wrmsr_unsafe



    .globl  intrinsic_invept
    .type   intrinsic_invept, @function
intrinsic_invept:

    invept rsi, [rdi]

    ret
    int 3

    .size intrinsic_invept, .-intrinsic_invept



    .globl  intrinsic_invvpid
    .type   intrinsic_invvpid, @function
intrinsic_invvpid:

    invept rsi, [rdi]

    ret
    int 3

    .size intrinsic_invvpid, .-intrinsic_invvpid



    .globl  intrinsic_vmld
    .type   intrinsic_vmld, @function
intrinsic_vmld:

    vmptrld [rdi]
    jbe intrinsic_vmld_failure

    xor rax, rax
    ret
    int 3

intrinsic_vmld_failure:

    mov rax, 0x4400
    vmread rax, rax

    ret
    int 3

    .size intrinsic_vmld, .-intrinsic_vmld




    .globl  intrinsic_vmcl
    .type   intrinsic_vmcl, @function
intrinsic_vmcl:

    vmclear [rdi]
    jbe intrinsic_vmcl_failure

    xor rax, rax
    ret
    int 3

intrinsic_vmcl_failure:

    mov rax, 0x4400
    vmread rax, rax

    ret
    int 3

    .size intrinsic_vmcl, .-intrinsic_vmcl



    .globl  intrinsic_vmrd16
    .type   intrinsic_vmrd16, @function
intrinsic_vmrd16:

    vmread rax, rdi
    jbe intrinsic_vmrd16_failure

    mov [rsi], ax
    xor rax, rax
    ret
    int 3

intrinsic_vmrd16_failure:

    mov rax, 0x4400
    vmread rax, rax

    ret
    int 3

    .size intrinsic_vmrd16, .-intrinsic_vmrd16



    .globl  intrinsic_vmrd32
    .type   intrinsic_vmrd32, @function
intrinsic_vmrd32:

    vmread rax, rdi
    jbe intrinsic_vmrd32_failure

    mov [rsi], eax
    xor rax, rax
    ret
    int 3

intrinsic_vmrd32_failure:

    mov rax, 0x4400
    vmread rax, rax

    ret
    int 3

    .size intrinsic_vmrd32, .-intrinsic_vmrd32



    .globl  intrinsic_vmrd64
    .type   intrinsic_vmrd64, @function
intrinsic_vmrd64:

    vmread rax, rdi
    jbe intrinsic_vmrd64_failure

    mov [rsi], rax
    xor rax, rax
    ret
    int 3

intrinsic_vmrd64_failure:

    mov rax, 0x4400
    vmread rax, rax

    ret
    int 3

    .size intrinsic_vmrd64, .-intrinsic_vmrd64



    .globl  intrinsic_vmwr16
    .type   intrinsic_vmwr16, @function
intrinsic_vmwr16:

    vmwrite rdi, rsi
    jbe intrinsic_vmwr16_failure

    xor rax, rax
    ret
    int 3

intrinsic_vmwr16_failure:

    mov rax, 0x4400
    vmread rax, rax

    ret
    int 3

    .size intrinsic_vmwr16, .-intrinsic_vmwr16



    .globl  intrinsic_vmwr32
    .type   intrinsic_vmwr32, @function
intrinsic_vmwr32:

    vmwrite rdi, rsi
    jbe intrinsic_vmwr32_failure

    xor rax, rax
    ret
    int 3

intrinsic_vmwr32_failure:

    mov rax, 0x4400
    vmread rax, rax

    ret
    int 3

    .size intrinsic_vmwr32, .-intrinsic_vmwr32



    .globl  intrinsic_vmwr64
    .type   intrinsic_vmwr64, @function
intrinsic_vmwr64:

    vmwrite rdi, rsi
    jbe intrinsic_vmwr64_failure

    xor rax, rax
    ret
    int 3

intrinsic_vmwr64_failure:

    mov rax, 0x4400
    vmread rax, rax

    ret
    int 3

    .size intrinsic_vmwr64, .-intrinsic_vmwr64



    .globl  intrinsic_vmwrfunc
    .type   intrinsic_vmwrfunc, @function
intrinsic_vmwrfunc:

    vmwrite rdi, rsi
    jbe intrinsic_vmwrfunc_failure

    xor rax, rax
    ret
    int 3

intrinsic_vmwrfunc_failure:

    mov rax, 0x4400
    vmread rax, rax

    ret
    int 3

    .size intrinsic_vmwrfunc, .-intrinsic_vmwrfunc



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
    /* CR2/DR6                                                                */
    /**************************************************************************/

    mov rax, [r15 + 0x000]
    mov cr2, rax

    mov rax, [r15 + 0x008]
    mov dr6, rax

    /**************************************************************************/
    /* MSRs                                                                   */
    /**************************************************************************/

    mov edi, 0xC0000081
    mov rsi, [r15 + 0x010]
    call intrinsic_wrmsr_unsafe

    mov edi, 0xC0000082
    mov rsi, [r15 + 0x018]
    call intrinsic_wrmsr_unsafe

    mov edi, 0xC0000083
    mov rsi, [r15 + 0x020]
    call intrinsic_wrmsr_unsafe

    mov edi, 0xC0000084
    mov rsi, [r15 + 0x028]
    call intrinsic_wrmsr_unsafe

    mov edi, 0xC0000102
    mov rsi, [r15 + 0x030]
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

    mov rax, [r15 + 0x060]
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
    jmp intrinsic_vmrun_failure

launch:
    vmlaunch

intrinsic_vmrun_failure:

    pop r15

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
    mov [r15 + 0x030], rax
    mov rsi, [r15 + 0x058]
    call intrinsic_wrmsr_unsafe

    mov edi, 0xC0000084
    call intrinsic_rdmsr_unsafe
    mov [r15 + 0x028], rax
    mov rsi, [r15 + 0x050]
    call intrinsic_wrmsr_unsafe

    mov edi, 0xC0000083
    call intrinsic_rdmsr_unsafe
    mov [r15 + 0x020], rax
    mov rsi, [r15 + 0x048]
    call intrinsic_wrmsr_unsafe

    mov edi, 0xC0000082
    call intrinsic_rdmsr_unsafe
    mov [r15 + 0x018], rax
    mov rsi, [r15 + 0x040]
    call intrinsic_wrmsr_unsafe

    mov edi, 0xC0000081
    call intrinsic_rdmsr_unsafe
    mov [r15 + 0x010], rax
    mov rsi, [r15 + 0x038]
    call intrinsic_wrmsr_unsafe

    /**************************************************************************/
    /* CR2                                                                    */
    /**************************************************************************/

    mov rax, dr6
    mov [r15 + 0x008], rax

    mov rax, cr2
    mov [r15 + 0x000], rax

    /**************************************************************************/
    /* Done                                                                   */
    /**************************************************************************/

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx

    mov rax, 0x4400
    vmread rax, rax
    mov rdx, 0xFFFFFFFF00000000
    or rax, rdx

    ret
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
    mov [r15 + 0x060], rax

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
    mov [r15 + 0x030], rax
    mov rsi, [r15 + 0x058]
    call intrinsic_wrmsr_unsafe

    mov edi, 0xC0000084
    call intrinsic_rdmsr_unsafe
    mov [r15 + 0x028], rax
    mov rsi, [r15 + 0x050]
    call intrinsic_wrmsr_unsafe

    mov edi, 0xC0000083
    call intrinsic_rdmsr_unsafe
    mov [r15 + 0x020], rax
    mov rsi, [r15 + 0x048]
    call intrinsic_wrmsr_unsafe

    mov edi, 0xC0000082
    call intrinsic_rdmsr_unsafe
    mov [r15 + 0x018], rax
    mov rsi, [r15 + 0x040]
    call intrinsic_wrmsr_unsafe

    mov edi, 0xC0000081
    call intrinsic_rdmsr_unsafe
    mov [r15 + 0x010], rax
    mov rsi, [r15 + 0x038]
    call intrinsic_wrmsr_unsafe

    /**************************************************************************/
    /* CR2                                                                    */
    /**************************************************************************/

    mov rax, dr6
    mov [r15 + 0x008], rax

    mov rax, cr2
    mov [r15 + 0x000], rax

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

    .size intrinsic_vmexit, .-intrinsic_vmexit
