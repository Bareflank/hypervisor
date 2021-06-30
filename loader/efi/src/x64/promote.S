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

    /** @brief defines the offset of state_save_t.rax */
    #define SS_OFFSET_RAX 0x000
    /** @brief defines the offset of state_save_t.rbx */
    #define SS_OFFSET_RBX 0x008
    /** @brief defines the offset of state_save_t.rcx */
    #define SS_OFFSET_RCX 0x010
    /** @brief defines the offset of state_save_t.rdx */
    #define SS_OFFSET_RDX 0x018
    /** @brief defines the offset of state_save_t.rbp */
    #define SS_OFFSET_RBP 0x020
    /** @brief defines the offset of state_save_t.rsi */
    #define SS_OFFSET_RSI 0x028
    /** @brief defines the offset of state_save_t.rdi */
    #define SS_OFFSET_RDI 0x030
    /** @brief defines the offset of state_save_t.r8 */
    #define SS_OFFSET_R8 0x038
    /** @brief defines the offset of state_save_t.r9 */
    #define SS_OFFSET_R9 0x040
    /** @brief defines the offset of state_save_t.r10 */
    #define SS_OFFSET_R10 0x048
    /** @brief defines the offset of state_save_t.r11 */
    #define SS_OFFSET_R11 0x050
    /** @brief defines the offset of state_save_t.r12 */
    #define SS_OFFSET_R12 0x058
    /** @brief defines the offset of state_save_t.r13 */
    #define SS_OFFSET_R13 0x060
    /** @brief defines the offset of state_save_t.r14 */
    #define SS_OFFSET_R14 0x068
    /** @brief defines the offset of state_save_t.r15 */
    #define SS_OFFSET_R15 0x070
    /** @brief defines the offset of state_save_t.rip */
    #define SS_OFFSET_RIP 0x078
    /** @brief defines the offset of state_save_t.rsp */
    #define SS_OFFSET_RSP 0x080
    /** @brief defines the offset of state_save_t.rflags */
    #define SS_OFFSET_RFLAGS 0x088
    /** @brief defines the offset of state_save_t.gdtr */
    #define SS_OFFSET_GDTR 0x0A0
    /** @brief defines the offset of state_save_t.idtr */
    #define SS_OFFSET_IDTR 0x0B0
    /** @brief defines the offset of state_save_t.es_selector */
    #define SS_OFFSET_ES_SELECTOR 0x0C0
    /** @brief defines the offset of state_save_t.cs_selector */
    #define SS_OFFSET_CS_SELECTOR 0x0D0
    /** @brief defines the offset of state_save_t.ss_selector */
    #define SS_OFFSET_SS_SELECTOR 0x0E0
    /** @brief defines the offset of state_save_t.ds_selector */
    #define SS_OFFSET_DS_SELECTOR 0x0F0
    /** @brief defines the offset of state_save_t.fs_selector */
    #define SS_OFFSET_FS_SELECTOR 0x100
    /** @brief defines the offset of state_save_t.gs_selector */
    #define SS_OFFSET_GS_SELECTOR 0x110
    /** @brief defines the offset of state_save_t.ldtr_selector */
    #define SS_OFFSET_LDTR_SELECTOR 0x120
    /** @brief defines the offset of state_save_t.tr_selector */
    #define SS_OFFSET_TR_SELECTOR 0x130
    /** @brief defines the offset of state_save_t.cr0 */
    #define SS_OFFSET_CR0 0x140
    /** @brief defines the offset of state_save_t.cr2 */
    #define SS_OFFSET_CR2 0x150
    /** @brief defines the offset of state_save_t.cr3 */
    #define SS_OFFSET_CR3 0x158
    /** @brief defines the offset of state_save_t.cr4 */
    #define SS_OFFSET_CR4 0x160
    /** @brief defines the offset of state_save_t.dr6 */
    #define SS_OFFSET_DR6 0x1F0
    /** @brief defines the offset of state_save_t.dr7 */
    #define SS_OFFSET_DR7 0x1F8
    /** @brief defines the offset of state_save_t.ia32_efer */
    #define SS_OFFSET_IA32_EFER 0x240
    /** @brief defines the offset of state_save_t.ia32_star */
    #define SS_OFFSET_IA32_STAR 0x248
    /** @brief defines the offset of state_save_t.ia32_lstar */
    #define SS_OFFSET_IA32_LSTAR 0x250
    /** @brief defines the offset of state_save_t.ia32_cstar */
    #define SS_OFFSET_IA32_CSTAR 0x258
    /** @brief defines the offset of state_save_t.ia32_fmask */
    #define SS_OFFSET_IA32_FMASK 0x260
    /** @brief defines the offset of state_save_t.ia32_fs_base */
    #define SS_OFFSET_IA32_FS_BASE 0x268
    /** @brief defines the offset of state_save_t.ia32_gs_base */
    #define SS_OFFSET_IA32_GS_BASE 0x270
    /** @brief defines the offset of state_save_t.ia32_kernel_gs_base */
    #define SS_OFFSET_IA32_KERNEL_GS_BASE 0x278
    /** @brief defines the offset of state_save_t.ia32_sysenter_cs */
    #define SS_OFFSET_IA32_SYSENTER_CS 0x280
    /** @brief defines the offset of state_save_t.ia32_sysenter_esp */
    #define SS_OFFSET_IA32_SYSENTER_ESP 0x288
    /** @brief defines the offset of state_save_t.ia32_sysenter_eip */
    #define SS_OFFSET_IA32_SYSENTER_EIP 0x290
    /** @brief defines the offset of state_save_t.ia32_pat */
    #define SS_OFFSET_IA32_PAT 0x298
    /** @brief defines the offset of state_save_t.ia32_debugctl */
    #define SS_OFFSET_IA32_DEBUGCTL 0x2A0
    /** @brief defines the offset of state_save_t.nmi */
    #define SS_OFFSET_NMI 0x318

    /** @brief defines MSR_IA32_SYSENTER_CS */
    #define MSR_IA32_SYSENTER_CS 0x00000174
    /** @brief defines MSR_IA32_SYSENTER_ESP */
    #define MSR_IA32_SYSENTER_ESP 0x00000175
    /** @brief defines MSR_IA32_SYSENTER_EIP */
    #define MSR_IA32_SYSENTER_EIP 0x00000176
    /** @brief defines MSR_IA32_DEBUGCTL */
    #define MSR_IA32_DEBUGCTL 0x000001D9
    /** @brief defines MSR_IA32_PAT */
    #define MSR_IA32_PAT 0x00000277
    /** @brief defines MSR_IA32_EFER */
    #define MSR_IA32_EFER 0xC0000080
    /** @brief defines MSR_IA32_STAR */
    #define MSR_IA32_STAR 0xC0000081
    /** @brief defines MSR_IA32_LSTAR */
    #define MSR_IA32_LSTAR 0xC0000082
    /** @brief defines MSR_IA32_CSTAR */
    #define MSR_IA32_CSTAR 0xC0000083
    /** @brief defines MSR_IA32_FMASK */
    #define MSR_IA32_FMASK 0xC0000084
    /** @brief defines MSR_IA32_FS_BASE */
    #define MSR_IA32_FS_BASE 0xC0000100
    /** @brief defines MSR_IA32_GS_BASE */
    #define MSR_IA32_GS_BASE 0xC0000101
    /** @brief defines MSR_IA32_KERNEL_GS_BASE */
    #define MSR_IA32_KERNEL_GS_BASE 0xC0000102

    .code64
    .intel_syntax noprefix

    .globl  promote
    .align  0x1000
promote:

    /**************************************************************************/
    /* Debug Registers                                                        */
    /**************************************************************************/

    mov rax, [r15 + SS_OFFSET_DR7]
    mov dr7, rax

    mov rax, [r15 + SS_OFFSET_DR6]
    mov dr6, rax

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

    mov rax, [r15 + SS_OFFSET_CR3]
    and rax, 0xFFFFFFFFFFFFF000
    mov cr3, rax

    mov rax, [r15 + SS_OFFSET_CR4]
    and rax, 0xFFFFFFFFFFFFFF7F
    mov cr4, rax

    mov rax, [r15 + SS_OFFSET_CR3]
    mov cr3, rax

    mov rax, [r15 + SS_OFFSET_CR4]
    mov cr4, rax

    mov rax, [r15 + SS_OFFSET_CR2]
    mov cr2, rax

    mov rax, [r15 + SS_OFFSET_CR0]
    mov cr0, rax

    /**************************************************************************/
    /* Stack                                                                  */
    /**************************************************************************/

    mov rsp, [r15 + SS_OFFSET_RSP]

    /**************************************************************************/
    /* Clear TSS Busy                                                         */
    /**************************************************************************/

    /**
     * NOTE:
     * - The TR in the GDT used by the root OS is marked as busy, and as
     *   a result, cannot be loaded without first marking it as available.
     */

    mov rdx, [r15 + 0x0A2]

    xor rax, rax
    mov ax, [r15 + 0x130]

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

    lgdt [r15 + SS_OFFSET_GDTR]

    mov dx, [r15 + SS_OFFSET_ES_SELECTOR]
    mov es, dx

    mov ax, [r15 + SS_OFFSET_CS_SELECTOR]
    push rax

    mov dx, [r15 + SS_OFFSET_SS_SELECTOR]
    mov ss, dx

    mov dx, [r15 + SS_OFFSET_DS_SELECTOR]
    mov ds, dx

    mov dx, [r15 + SS_OFFSET_FS_SELECTOR]
    mov fs, dx

    mov dx, [r15 + SS_OFFSET_GS_SELECTOR]
    mov gs, dx

    mov dx, [r15 + SS_OFFSET_LDTR_SELECTOR]
    lldt dx

    mov dx, [r15 + SS_OFFSET_TR_SELECTOR]
    ltr dx

    lea rax, [rip + gdt_and_cs_loaded]
    push rax

    retfq

gdt_and_cs_loaded:

    /**************************************************************************/
    /* MSRs                                                                   */
    /**************************************************************************/

    mov ecx, MSR_IA32_DEBUGCTL
    mov eax, [r15 + SS_OFFSET_IA32_DEBUGCTL + 0x0]
    mov edx, [r15 + SS_OFFSET_IA32_DEBUGCTL + 0x4]
    wrmsr

    mov ecx, MSR_IA32_PAT
    mov eax, [r15 + SS_OFFSET_IA32_PAT + 0x0]
    mov edx, [r15 + SS_OFFSET_IA32_PAT + 0x4]
    wrmsr

    mov ecx, MSR_IA32_SYSENTER_EIP
    mov eax, [r15 + SS_OFFSET_IA32_SYSENTER_EIP + 0x0]
    mov edx, [r15 + SS_OFFSET_IA32_SYSENTER_EIP + 0x4]
    wrmsr

    mov ecx, MSR_IA32_SYSENTER_EIP
    mov eax, [r15 + SS_OFFSET_IA32_SYSENTER_EIP + 0x0]
    mov edx, [r15 + SS_OFFSET_IA32_SYSENTER_EIP + 0x4]
    wrmsr

    mov ecx, MSR_IA32_SYSENTER_CS
    mov eax, [r15 + SS_OFFSET_IA32_SYSENTER_CS + 0x0]
    mov edx, [r15 + SS_OFFSET_IA32_SYSENTER_CS + 0x4]
    wrmsr

    mov ecx, MSR_IA32_KERNEL_GS_BASE
    mov eax, [r15 + SS_OFFSET_IA32_KERNEL_GS_BASE + 0x0]
    mov edx, [r15 + SS_OFFSET_IA32_KERNEL_GS_BASE + 0x4]
    wrmsr

    mov ecx, MSR_IA32_GS_BASE
    mov eax, [r15 + SS_OFFSET_IA32_GS_BASE + 0x0]
    mov edx, [r15 + SS_OFFSET_IA32_GS_BASE + 0x4]
    wrmsr

    mov ecx, MSR_IA32_FS_BASE
    mov eax, [r15 + SS_OFFSET_IA32_FS_BASE + 0x0]
    mov edx, [r15 + SS_OFFSET_IA32_FS_BASE + 0x4]
    wrmsr

    mov ecx, MSR_IA32_FMASK
    mov eax, [r15 + SS_OFFSET_IA32_FMASK + 0x0]
    mov edx, [r15 + SS_OFFSET_IA32_FMASK + 0x4]
    wrmsr

    mov ecx, MSR_IA32_CSTAR
    mov eax, [r15 + SS_OFFSET_IA32_CSTAR + 0x0]
    mov edx, [r15 + SS_OFFSET_IA32_CSTAR + 0x4]
    wrmsr

    mov ecx, MSR_IA32_LSTAR
    mov eax, [r15 + SS_OFFSET_IA32_LSTAR + 0x0]
    mov edx, [r15 + SS_OFFSET_IA32_LSTAR + 0x4]
    wrmsr

    mov ecx, MSR_IA32_STAR
    mov eax, [r15 + SS_OFFSET_IA32_STAR + 0x0]
    mov edx, [r15 + SS_OFFSET_IA32_STAR + 0x4]
    wrmsr

    mov ecx, MSR_IA32_EFER
    mov eax, [r15 + SS_OFFSET_IA32_EFER + 0x0]
    mov edx, [r15 + SS_OFFSET_IA32_EFER + 0x4]
    wrmsr

    /**************************************************************************/
    /* IDT                                                                    */
    /**************************************************************************/

    lidt [r15 + SS_OFFSET_IDTR]

    /**************************************************************************/
    /* NMIs                                                                   */
    /**************************************************************************/

    mov rax, [r15 + SS_OFFSET_NMI]
    cmp rax, 0x1
    jne nmis_complete

    int 2

nmis_complete:

    /**************************************************************************/
    /* Flags                                                                  */
    /**************************************************************************/

    push qword ptr[r15 + SS_OFFSET_RFLAGS]
    popfq

    /**************************************************************************/
    /* General Purpose Registers                                              */
    /**************************************************************************/

    mov rax, [r15 + SS_OFFSET_RIP]
    push rax

    mov r14, [r15 + SS_OFFSET_R14]
    mov r13, [r15 + SS_OFFSET_R13]
    mov r12, [r15 + SS_OFFSET_R12]
    mov r11, [r15 + SS_OFFSET_R11]
    mov r10, [r15 + SS_OFFSET_R10]
    mov r9,  [r15 + SS_OFFSET_R9]
    mov r8,  [r15 + SS_OFFSET_R8]
    mov rdi, [r15 + SS_OFFSET_RDI]
    mov rsi, [r15 + SS_OFFSET_RSI]
    mov rbp, [r15 + SS_OFFSET_RBP]
    mov rdx, [r15 + SS_OFFSET_RDX]
    mov rcx, [r15 + SS_OFFSET_RCX]
    mov rbx, [r15 + SS_OFFSET_RBX]
    mov rax, [r15 + SS_OFFSET_RAX]

    mov r15, [r15 + SS_OFFSET_R15]

    call enable_interrupts
    ret
    int 3
