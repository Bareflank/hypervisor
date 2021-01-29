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

    .globl  promote
    .align  0x1000
promote:
    UNWIND_HINT_EMPTY

    /**************************************************************************/
    /* Debug Registers                                                        */
    /**************************************************************************/

    mov rax, [r15 + 0x1F8]
    mov dr7, rax

    mov rax, [r15 + 0x1F0]
    mov dr6, rax

    /**************************************************************************/
    /* Clear TSS Busy                                                         */
    /**************************************************************************/

    /**
     * NOTE:
     * - The TR in the GDT used by the root OS is marked as busy, and as
     *   a result, cannot be loaded without first marking it as available.
     * - Some OS's like Linux mark the GDT as read-only, and will not provide
     *   the physical address of the GDT, which means the microkernel needs
     *   to walk the root OS's page tables to locate the physical address
     *   and then map it into the microkernel's page tables. Once this is
     *   done, we can clear the TSS busy bit. If the microkernel fails to
     *   perform at least this operation, it will halt with no means to
     *   return as it cannot promote the GDT portion of the root OS's state.
     */

    mov rdx, [r15 + 0x0A2]

    xor rax, rax
    mov ax, [r15 + 0x130]
    and ax, 0xF8

    add rdx, rax

    mov rax, 0xFFFFFDFFFFFFFFFF
    and [rdx], rax

    /**************************************************************************/
    /* GDT                                                                    */
    /**************************************************************************/

    /**
     * Notes:
     * - Before we can restore the GDT, we need to clear the TSS Busy bit. This
     *   is because the TSS that the OS was using was busy when it was replaced
     *   and you cannot load TR with a segment descriptor that is marked as
     *   busy.
     * - To clear the TSS Busy bit we must get the address of the GDT and
     *   then use the TR selector to get the TSS segment descriptor and clear
     *   the TSS Busy bit. This way, when TR is loaded, it is loaded with
     *   a properly set up TSS segment descriptor.
     * - On Linux, the GDT is marked usually as read-only, so there is code
     *   in the platform logic to mark the GDT as read/write just in case
     *   this code needs to execute.
     */

    lgdt [r15 + 0x0A0]

    mov dx, [r15 + 0x0C0]
    mov es, dx

    mov ax, [r15 + 0x0D0]
    push rax

    mov dx, [r15 + 0x0E0]
    mov ss, dx

    mov dx, [r15 + 0x0F0]
    mov ds, dx

    mov dx, [r15 + 0x100]
    mov fs, dx

    mov dx, [r15 + 0x110]
    mov gs, dx

    mov dx, [r15 + 0x120]
    lldt dx

    mov dx, [r15 + 0x130]
    ltr dx

    lea rax, [rip + gdt_and_cs_loaded]
    push rax

    retfq
    int3     /** remove straight-line speculation, unreachable */

gdt_and_cs_loaded:

    /**************************************************************************/
    /* Control Registers                                                      */
    /**************************************************************************/

    /**
     * Notes:
     * - When we promote the OS, we need to handle PCID properly. This is
     *   done by clearing PCID in CR3, setting CR4 and then putting the actual
     *   CR3 value into CR3. That's why we set CR3 twice here.
     * - We also need to handle global paging properly. Once we got back to
     *   the OS, pages from the microkernel should be flushed from the TLB.
     *   The safest way to do that is to clear the global paging bit which
     *   will do a complete TLB flush.
     * - Finally, we need to load a new stack pointer once we load the new
     *   CR3 so that we can push/pop as needed
     */

    mov rax, [r15 + 0x158]
    and rax, 0xFFFFFFFFFFFFF000
    mov cr3, rax

    mov rax, [r15 + 0x160]
    and rax, 0xFFFFFFFFFFFFFF7F
    mov cr4, rax

    mov rax, [r15 + 0x158]
    mov cr3, rax

    mov rax, [r15 + 0x160]
    mov cr4, rax

    mov rax, [r15 + 0x150]
    mov cr2, rax

    mov rax, [r15 + 0x140]
    mov cr0, rax

    mov rsp, [r15 + 0x080]

    /**************************************************************************/
    /* MSRs                                                                   */
    /**************************************************************************/

    mov ecx, 0x000001D9      /* DEBUGCTL */
    mov eax, [r15 + 0x2A0]
    mov edx, [r15 + 0x2A4]
    wrmsr

    mov ecx, 0x00000277      /* PAT */
    mov eax, [r15 + 0x298]
    mov edx, [r15 + 0x29C]
    wrmsr

    mov ecx, 0x00000176      /* SYSENTER_EIP */
    mov eax, [r15 + 0x290]
    mov edx, [r15 + 0x294]
    wrmsr

    mov ecx, 0x00000175      /* SYSENTER_ESP */
    mov eax, [r15 + 0x288]
    mov edx, [r15 + 0x28C]
    wrmsr

    mov ecx, 0x00000174      /* SYSENTER_CS */
    mov eax, [r15 + 0x280]
    mov edx, [r15 + 0x284]
    wrmsr

    mov ecx, 0xC0000102      /* Kernel GS Base */
    mov eax, [r15 + 0x278]
    mov edx, [r15 + 0x27C]
    wrmsr

    mov ecx, 0xC0000101      /* GS Base */
    mov eax, [r15 + 0x270]
    mov edx, [r15 + 0x274]
    wrmsr

    mov ecx, 0xC0000100      /* FS Base */
    mov eax, [r15 + 0x268]
    mov edx, [r15 + 0x26C]
    wrmsr

    mov ecx, 0xC0000084      /* FMASK */
    mov eax, [r15 + 0x260]
    mov edx, [r15 + 0x264]
    wrmsr

    mov ecx, 0xC0000083      /* CSTAR */
    mov eax, [r15 + 0x258]
    mov edx, [r15 + 0x25C]
    wrmsr

    mov ecx, 0xC0000082      /* LSTAR */
    mov eax, [r15 + 0x250]
    mov edx, [r15 + 0x254]
    wrmsr

    mov ecx, 0xC0000081      /* STAR */
    mov eax, [r15 + 0x248]
    mov edx, [r15 + 0x24C]
    wrmsr

    mov ecx, 0xC0000080      /* EFER */
    mov eax, [r15 + 0x240]
    mov edx, [r15 + 0x244]
    wrmsr

    /**************************************************************************/
    /* IDT                                                                    */
    /**************************************************************************/

    lidt [r15 + 0x0B0]

    /**************************************************************************/
    /* NMIs                                                                   */
    /**************************************************************************/

    mov rax, [r15 + 0x318]
    cmp rax, 0x1
    jne nmis_complete

    int 2

nmis_complete:

    /**************************************************************************/
    /* Flags                                                                  */
    /**************************************************************************/

    push [r15 + 0x088]
    popf

    /**************************************************************************/
    /* General Purpose Registers                                              */
    /**************************************************************************/

    mov rax, [r15 + 0x078]
    push rax

    mov r14, [r15 + 0x068]
    mov r13, [r15 + 0x060]
    mov r12, [r15 + 0x058]
    mov r11, [r15 + 0x050]
    mov r10, [r15 + 0x048]
    mov r9,  [r15 + 0x040]
    mov r8,  [r15 + 0x038]
    mov rdi, [r15 + 0x030]
    mov rsi, [r15 + 0x028]
    mov rbp, [r15 + 0x020]
    mov rdx, [r15 + 0x018]
    mov rcx, [r15 + 0x010]
    mov rbx, [r15 + 0x008]
    mov rax, [r15 + 0x000]

    mov r15, [r15 + 0x070]

    call enable_interrupts
    ret

    .size promote, 0x1000
