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

#include <asm/unwind_hints.h>

    .code64
    .intel_syntax noprefix

    .globl  demote
    .align  0x1000
demote:
    UNWIND_HINT_EMPTY

    /**************************************************************************/
    /* General Purpose Registers                                              */
    /**************************************************************************/

    mov [rdx + 0x000], rax
    mov [rdx + 0x008], rbx
    mov [rdx + 0x010], rcx
    mov [rdx + 0x018], rdx
    mov [rdx + 0x020], rbp
    mov [rdx + 0x028], rsi
    mov [rdx + 0x030], rdi
    mov [rdx + 0x038], r8
    mov [rdx + 0x040], r9
    mov [rdx + 0x048], r10
    mov [rdx + 0x050], r11
    mov [rdx + 0x058], r12
    mov [rdx + 0x060], r13
    mov [rdx + 0x068], r14
    mov [rdx + 0x070], r15

    lea rax, [rip + demotion_success]
    mov [rdx + 0x078], rax
    mov [rdx + 0x080], rsp

    /**************************************************************************/
    /* Setup                                                                  */
    /**************************************************************************/

    mov r13, rdi       /* args */
    mov r14, rsi       /* mk_state */
    mov r15, rdx       /* root_vp_state */

    /**************************************************************************/
    /* Flags                                                                  */
    /**************************************************************************/

    pushf
    pop [r15 + 0x088]
    push [r14 + 0x088]
    popf

    /**************************************************************************/
    /* IDT                                                                    */
    /**************************************************************************/

    call disable_interrupts

    sidt [r15 + 0x0B0]
    lidt [r14 + 0x0B0]

    /**************************************************************************/
    /* MSRs                                                                   */
    /**************************************************************************/

    mov ecx, 0xC0000080      /* EFER */
    rdmsr
    mov [r15 + 0x240], eax
    mov [r15 + 0x244], edx
    mov eax, [r14 + 0x240]
    mov edx, [r14 + 0x244]
    wrmsr

    mov ecx, 0xC0000081      /* STAR */
    rdmsr
    mov [r15 + 0x248], eax
    mov [r15 + 0x24C], edx
    mov eax, [r14 + 0x248]
    mov edx, [r14 + 0x24C]
    wrmsr

    mov ecx, 0xC0000082      /* LSTAR */
    rdmsr
    mov [r15 + 0x250], eax
    mov [r15 + 0x254], edx
    mov eax, [r14 + 0x250]
    mov edx, [r14 + 0x254]
    wrmsr

    mov ecx, 0xC0000083      /* CSTAR */
    rdmsr
    mov [r15 + 0x258], eax
    mov [r15 + 0x25C], edx
    mov eax, [r14 + 0x258]
    mov edx, [r14 + 0x25C]
    wrmsr

    mov ecx, 0xC0000084      /* FMASK */
    rdmsr
    mov [r15 + 0x260], eax
    mov [r15 + 0x264], edx
    mov eax, [r14 + 0x260]
    mov edx, [r14 + 0x264]
    wrmsr

    mov ecx, 0xC0000100      /* FS Base */
    rdmsr
    mov [r15 + 0x268], eax
    mov [r15 + 0x26C], edx
    mov eax, [r14 + 0x268]
    mov edx, [r14 + 0x26C]
    wrmsr

    mov ecx, 0xC0000101      /* GS Base */
    rdmsr
    mov [r15 + 0x270], eax
    mov [r15 + 0x274], edx
    mov eax, [r14 + 0x270]
    mov edx, [r14 + 0x274]
    wrmsr

    mov ecx, 0xC0000102      /* Kernel GS Base */
    rdmsr
    mov [r15 + 0x278], eax
    mov [r15 + 0x27C], edx
    mov eax, [r14 + 0x278]
    mov edx, [r14 + 0x27C]
    wrmsr

    mov ecx, 0x00000174      /* SYSENTER_CS */
    rdmsr
    mov [r15 + 0x280], eax
    mov [r15 + 0x284], edx
    mov eax, [r14 + 0x280]
    mov edx, [r14 + 0x284]
    wrmsr

    mov ecx, 0x00000175      /* SYSENTER_ESP */
    rdmsr
    mov [r15 + 0x288], eax
    mov [r15 + 0x28C], edx
    mov eax, [r14 + 0x288]
    mov edx, [r14 + 0x28C]
    wrmsr

    mov ecx, 0x00000176      /* SYSENTER_EIP */
    rdmsr
    mov [r15 + 0x290], eax
    mov [r15 + 0x294], edx
    mov eax, [r14 + 0x290]
    mov edx, [r14 + 0x294]
    wrmsr

    mov ecx, 0x00000277      /* PAT */
    rdmsr
    mov [r15 + 0x298], eax
    mov [r15 + 0x29C], edx
    mov eax, [r14 + 0x298]
    mov edx, [r14 + 0x29C]
    wrmsr

    mov ecx, 0x000001D9      /* DEBUGCTL */
    rdmsr
    mov [r15 + 0x2A0], eax
    mov [r15 + 0x2A4], edx
    mov eax, [r14 + 0x2A0]
    mov edx, [r14 + 0x2A4]
    wrmsr

    /**************************************************************************/
    /* GDT                                                                    */
    /**************************************************************************/

    sgdt [r15 + 0x0A0]
    lgdt [r14 + 0x0A0]

    mov dx, es
    mov [r15 + 0x0C0], dx
    mov dx, [r14 + 0x0C0]
    mov es, dx

    mov dx, cs
    mov [r15 + 0x0D0], dx
    mov ax, [r14 + 0x0D0]
    push rax

    mov dx, ss
    mov [r15 + 0x0E0], dx
    mov dx, [r14 + 0x0E0]
    mov ss, dx

    mov dx, ds
    mov [r15 + 0x0F0], dx
    mov dx, [r14 + 0x0F0]
    mov ds, dx

    mov dx, fs
    mov [r15 + 0x100], dx
    mov dx, [r14 + 0x100]
    mov fs, dx

    mov dx, gs
    mov [r15 + 0x110], dx
    mov dx, [r14 + 0x110]
    mov gs, dx

    mov ecx, 0x000001D9
    xor rax, rax
    xor rdx, rdx
    mov ax, [r14 + 0x110]
    wrmsr

    sldt dx
    mov [r15 + 0x120], dx
    mov dx, [r14 + 0x120]
    lldt dx

    str dx
    mov [r15 + 0x130], dx
    mov dx, [r14 + 0x130]
    ltr dx

    lea rax, [rip + gdt_and_cs_loaded]
    push rax

    retfq

gdt_and_cs_loaded:

    /**************************************************************************/
    /* Control Registers                                                      */
    /**************************************************************************/

    mov rax, cr0
    mov [r15 + 0x140], rax
    mov rax, [r14 + 0x140]
    mov cr0, rax

    mov rax, cr2
    mov [r15 + 0x150], rax
    mov rax, [r14 + 0x150]
    mov cr2, rax

    mov rax, cr4
    mov [r15 + 0x160], rax
    mov rax, [r14 + 0x160]
    mov cr4, rax

    mov rax, cr3
    mov [r15 + 0x158], rax
    mov rax, [r14 + 0x158]
    mov cr3, rax

    mov rsp, [r14 + 0x080]

    /**************************************************************************/
    /* Debug Registers                                                        */
    /**************************************************************************/

    mov rax, dr6
    mov [r15 + 0x1F0], rax
    mov rax, [r14 + 0x1F0]
    mov dr6, rax

    mov rax, dr7
    mov [r15 + 0x1F8], rax
    mov rax, [r14 + 0x1F8]
    mov dr7, rax

    /**************************************************************************/
    /* Call Microkernel                                                       */
    /**************************************************************************/

    mov rdi, r13
    push [r14 + 0x078]
    ret
    int 3

demotion_success:

    /**
     * NOTE:
     * - If demotion is successful, before we return back to the loader, we
     *   ensure that at least one exit occurs. This is done to properly handle
     *   errors with the first VMExit. Specifically, if the first VMExit
     *   generates a failure, it needs to return to loader. The state in
     *   the root VP, which is what it will use to return is still the same
     *   at this point, so a return is safe.
     */

    push rax
    push rbx
    push rcx
    push rdx

    mov rax, 0
    cpuid

    pop rdx
    pop rcx
    pop rbx
    pop rax

    call enable_interrupts
    ret
    int 3

    .size demote, 0x1000
