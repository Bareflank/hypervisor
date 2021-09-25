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
    /** @brief defines the offset of state_save_t.cr8 */
    #define SS_OFFSET_CR8 0x168
    /** @brief defines the offset of state_save_t.xcr0 */
    #define SS_OFFSET_XCR0 0x170
    /** @brief defines the offset of state_save_t.dr0 */
    #define SS_OFFSET_DR0 0x1C0
    /** @brief defines the offset of state_save_t.dr1 */
    #define SS_OFFSET_DR1 0x1C8
    /** @brief defines the offset of state_save_t.dr2 */
    #define SS_OFFSET_DR2 0x1D0
    /** @brief defines the offset of state_save_t.dr3 */
    #define SS_OFFSET_DR3 0x1D8
    /** @brief defines the offset of state_save_t.dr6 */
    #define SS_OFFSET_DR6 0x1F0
    /** @brief defines the offset of state_save_t.dr7 */
    #define SS_OFFSET_DR7 0x1F8
    /** @brief defines the offset of state_save_t.efer */
    #define SS_OFFSET_EFER 0x240
    /** @brief defines the offset of state_save_t.star */
    #define SS_OFFSET_STAR 0x248
    /** @brief defines the offset of state_save_t.lstar */
    #define SS_OFFSET_LSTAR 0x250
    /** @brief defines the offset of state_save_t.cstar */
    #define SS_OFFSET_CSTAR 0x258
    /** @brief defines the offset of state_save_t.fmask */
    #define SS_OFFSET_FMASK 0x260
    /** @brief defines the offset of state_save_t.fs_base */
    #define SS_OFFSET_FS_BASE 0x268
    /** @brief defines the offset of state_save_t.gs_base */
    #define SS_OFFSET_GS_BASE 0x270
    /** @brief defines the offset of state_save_t.kernel_gs_base */
    #define SS_OFFSET_KERNEL_GS_BASE 0x278
    /** @brief defines the offset of state_save_t.sysenter_cs */
    #define SS_OFFSET_SYSENTER_CS 0x280
    /** @brief defines the offset of state_save_t.sysenter_esp */
    #define SS_OFFSET_SYSENTER_ESP 0x288
    /** @brief defines the offset of state_save_t.sysenter_eip */
    #define SS_OFFSET_SYSENTER_EIP 0x290
    /** @brief defines the offset of state_save_t.pat */
    #define SS_OFFSET_PAT 0x298
    /** @brief defines the offset of state_save_t.debugctl */
    #define SS_OFFSET_DEBUGCTL 0x2A0

    /** @brief defines MSR_SYSENTER_CS */
    #define MSR_SYSENTER_CS 0x00000174
    /** @brief defines MSR_SYSENTER_ESP */
    #define MSR_SYSENTER_ESP 0x00000175
    /** @brief defines MSR_SYSENTER_EIP */
    #define MSR_SYSENTER_EIP 0x00000176
    /** @brief defines MSR_DEBUGCTL */
    #define MSR_DEBUGCTL 0x000001D9
    /** @brief defines MSR_PAT */
    #define MSR_PAT 0x00000277
    /** @brief defines MSR_EFER */
    #define MSR_EFER 0xC0000080
    /** @brief defines MSR_STAR */
    #define MSR_STAR 0xC0000081
    /** @brief defines MSR_LSTAR */
    #define MSR_LSTAR 0xC0000082
    /** @brief defines MSR_CSTAR */
    #define MSR_CSTAR 0xC0000083
    /** @brief defines MSR_FMASK */
    #define MSR_FMASK 0xC0000084
    /** @brief defines MSR_FS_BASE */
    #define MSR_FS_BASE 0xC0000100
    /** @brief defines MSR_GS_BASE */
    #define MSR_GS_BASE 0xC0000101
    /** @brief defines MSR_KERNEL_GS_BASE */
    #define MSR_KERNEL_GS_BASE 0xC0000102

    .code64
    .intel_syntax noprefix

    .globl  demote
    .align  0x1000
demote:

    /**************************************************************************/
    /* Report Success On Completion                                           */
    /**************************************************************************/

    xor rax, rax

    /**************************************************************************/
    /* General Purpose Registers                                              */
    /**************************************************************************/

    mov [r8 + SS_OFFSET_RAX], rax
    mov [r8 + SS_OFFSET_RBX], rbx
    mov [r8 + SS_OFFSET_RCX], rcx
    mov [r8 + SS_OFFSET_RDX], rdx
    mov [r8 + SS_OFFSET_RBP], rbp
    mov [r8 + SS_OFFSET_RSI], rsi
    mov [r8 + SS_OFFSET_RDI], rdi
    mov [r8 + SS_OFFSET_R8], r8
    mov [r8 + SS_OFFSET_R9], r9
    mov [r8 + SS_OFFSET_R10], r10
    mov [r8 + SS_OFFSET_R11], r11
    mov [r8 + SS_OFFSET_R12], r12
    mov [r8 + SS_OFFSET_R13], r13
    mov [r8 + SS_OFFSET_R14], r14
    mov [r8 + SS_OFFSET_R15], r15

    lea rax, [rip + demotion_return]
    mov [r8 + SS_OFFSET_RIP], rax
    mov [r8 + SS_OFFSET_RSP], rsp


    /**************************************************************************/
    /* Setup                                                                  */
    /**************************************************************************/

    mov r13, rcx       /* args */
    mov r14, rdx       /* mk_state */
    mov r15, r8        /* root_vp_state */

    /**************************************************************************/
    /* Flags                                                                  */
    /**************************************************************************/

    pushfq
    pop qword ptr[r15 + SS_OFFSET_RFLAGS]
    push qword ptr[r14 + SS_OFFSET_RFLAGS]
    popfq

    /**************************************************************************/
    /* IDT                                                                    */
    /**************************************************************************/

    call disable_interrupts

    sidt [r15 + SS_OFFSET_IDTR]
    lidt [r14 + SS_OFFSET_IDTR]

    /**************************************************************************/
    /* MSRs                                                                   */
    /**************************************************************************/

    mov ecx, MSR_EFER
    rdmsr
    mov [r15 + SS_OFFSET_EFER + 0x0], eax
    mov [r15 + SS_OFFSET_EFER + 0x4], edx
    mov eax, [r14 + SS_OFFSET_EFER + 0x0]
    mov edx, [r14 + SS_OFFSET_EFER + 0x4]
    wrmsr

    mov ecx, MSR_STAR
    rdmsr
    mov [r15 + SS_OFFSET_STAR + 0x0], eax
    mov [r15 + SS_OFFSET_STAR + 0x4], edx
    mov eax, [r14 + SS_OFFSET_STAR + 0x0]
    mov edx, [r14 + SS_OFFSET_STAR + 0x4]
    wrmsr

    mov ecx, MSR_LSTAR
    rdmsr
    mov [r15 + SS_OFFSET_LSTAR + 0x0], eax
    mov [r15 + SS_OFFSET_LSTAR + 0x4], edx
    mov eax, [r14 + SS_OFFSET_LSTAR + 0x0]
    mov edx, [r14 + SS_OFFSET_LSTAR + 0x4]
    wrmsr

    mov ecx, MSR_CSTAR
    rdmsr
    mov [r15 + SS_OFFSET_CSTAR + 0x0], eax
    mov [r15 + SS_OFFSET_CSTAR + 0x4], edx
    mov eax, [r14 + SS_OFFSET_CSTAR + 0x0]
    mov edx, [r14 + SS_OFFSET_CSTAR + 0x4]
    wrmsr

    mov ecx, MSR_FMASK
    rdmsr
    mov [r15 + SS_OFFSET_FMASK + 0x0], eax
    mov [r15 + SS_OFFSET_FMASK + 0x4], edx
    mov eax, [r14 + SS_OFFSET_FMASK + 0x0]
    mov edx, [r14 + SS_OFFSET_FMASK + 0x4]
    wrmsr

    mov ecx, MSR_FS_BASE
    rdmsr
    mov [r15 + SS_OFFSET_FS_BASE + 0x0], eax
    mov [r15 + SS_OFFSET_FS_BASE + 0x4], edx
    mov eax, [r14 + SS_OFFSET_FS_BASE + 0x0]
    mov edx, [r14 + SS_OFFSET_FS_BASE + 0x4]
    wrmsr

    mov ecx, MSR_GS_BASE
    rdmsr
    mov [r15 + SS_OFFSET_GS_BASE + 0x0], eax
    mov [r15 + SS_OFFSET_GS_BASE + 0x4], edx
    mov eax, [r14 + SS_OFFSET_GS_BASE + 0x0]
    mov edx, [r14 + SS_OFFSET_GS_BASE + 0x4]
    wrmsr

    mov ecx, MSR_KERNEL_GS_BASE
    rdmsr
    mov [r15 + SS_OFFSET_KERNEL_GS_BASE + 0x0], eax
    mov [r15 + SS_OFFSET_KERNEL_GS_BASE + 0x4], edx
    mov eax, [r14 + SS_OFFSET_KERNEL_GS_BASE + 0x0]
    mov edx, [r14 + SS_OFFSET_KERNEL_GS_BASE + 0x4]
    wrmsr

    mov ecx, MSR_SYSENTER_CS
    rdmsr
    mov [r15 + SS_OFFSET_SYSENTER_CS + 0x0], eax
    mov [r15 + SS_OFFSET_SYSENTER_CS + 0x4], edx
    mov eax, [r14 + SS_OFFSET_SYSENTER_CS + 0x0]
    mov edx, [r14 + SS_OFFSET_SYSENTER_CS + 0x4]
    wrmsr

    mov ecx, MSR_SYSENTER_ESP
    rdmsr
    mov [r15 + SS_OFFSET_SYSENTER_ESP + 0x0], eax
    mov [r15 + SS_OFFSET_SYSENTER_ESP + 0x4], edx
    mov eax, [r14 + SS_OFFSET_SYSENTER_ESP + 0x0]
    mov edx, [r14 + SS_OFFSET_SYSENTER_ESP + 0x4]
    wrmsr

    mov ecx, MSR_SYSENTER_EIP
    rdmsr
    mov [r15 + SS_OFFSET_SYSENTER_EIP + 0x0], eax
    mov [r15 + SS_OFFSET_SYSENTER_EIP + 0x4], edx
    mov eax, [r14 + SS_OFFSET_SYSENTER_EIP + 0x0]
    mov edx, [r14 + SS_OFFSET_SYSENTER_EIP + 0x4]
    wrmsr

    mov ecx, MSR_PAT
    rdmsr
    mov [r15 + SS_OFFSET_PAT + 0x0], eax
    mov [r15 + SS_OFFSET_PAT + 0x4], edx
    mov eax, [r14 + SS_OFFSET_PAT + 0x0]
    mov edx, [r14 + SS_OFFSET_PAT + 0x4]
    wrmsr

    mov ecx, MSR_DEBUGCTL
    rdmsr
    mov [r15 + SS_OFFSET_DEBUGCTL + 0x0], eax
    mov [r15 + SS_OFFSET_DEBUGCTL + 0x4], edx
    mov eax, [r14 + SS_OFFSET_DEBUGCTL + 0x0]
    mov edx, [r14 + SS_OFFSET_DEBUGCTL + 0x4]
    wrmsr

    /**************************************************************************/
    /* GDT                                                                    */
    /*************************************************************************/

    sgdt [r15 + SS_OFFSET_GDTR]
    lgdt [r14 + SS_OFFSET_GDTR]

    mov dx, es
    mov [r15 + SS_OFFSET_ES_SELECTOR], dx
    mov dx, [r14 + SS_OFFSET_ES_SELECTOR]
    mov es, dx

    mov dx, cs
    mov [r15 + SS_OFFSET_CS_SELECTOR], dx
    mov ax, [r14 + SS_OFFSET_CS_SELECTOR]
    push rax

    mov dx, ss
    mov [r15 + SS_OFFSET_SS_SELECTOR], dx
    mov dx, [r14 + SS_OFFSET_SS_SELECTOR]
    mov ss, dx

    mov dx, ds
    mov [r15 + SS_OFFSET_DS_SELECTOR], dx
    mov dx, [r14 + SS_OFFSET_DS_SELECTOR]
    mov ds, dx

    mov dx, fs
    mov [r15 + SS_OFFSET_FS_SELECTOR], dx
    mov dx, [r14 + SS_OFFSET_FS_SELECTOR]
    mov fs, dx

    mov dx, gs
    mov [r15 + SS_OFFSET_GS_SELECTOR], dx
    mov dx, [r14 + SS_OFFSET_GS_SELECTOR]
    mov gs, dx

    sldt dx
    mov [r15 + SS_OFFSET_LDTR_SELECTOR], dx
    mov dx, [r14 + SS_OFFSET_LDTR_SELECTOR]
    lldt dx

    str dx
    mov [r15 + SS_OFFSET_TR_SELECTOR], dx
    mov dx, [r14 + SS_OFFSET_TR_SELECTOR]
    ltr dx

    lea rax, [rip + gdt_and_cs_loaded]
    push rax

    retfq

gdt_and_cs_loaded:

    /**************************************************************************/
    /* Control Registers                                                      */
    /**************************************************************************/

    mov rax, cr0
    mov [r15 + SS_OFFSET_CR0], rax
    mov rax, [r14 + SS_OFFSET_CR0]
    mov cr0, rax

    mov rax, cr2
    mov [r15 + SS_OFFSET_CR2], rax
    mov rax, [r14 + SS_OFFSET_CR2]
    mov cr2, rax

    mov rax, cr4
    mov [r15 + SS_OFFSET_CR4], rax
    mov rax, [r14 + SS_OFFSET_CR4]
    mov cr4, rax

    mov rax, cr3
    mov [r15 + SS_OFFSET_CR3], rax
    mov rax, [r14 + SS_OFFSET_CR3]
    mov cr3, rax

    mov rax, cr8
    mov [r15 + SS_OFFSET_CR8], rax
    mov rax, [r14 + SS_OFFSET_CR8]
    mov cr8, rax

    xor ecx, ecx
    xgetbv
    mov [r15 + SS_OFFSET_XCR0 + 0x0], eax
    mov [r15 + SS_OFFSET_XCR0 + 0x4], edx
    mov eax, [r14 + SS_OFFSET_XCR0 + 0x0]
    mov edx, [r14 + SS_OFFSET_XCR0 + 0x4]
    xsetbv

    /**************************************************************************/
    /* Stack                                                                  */
    /**************************************************************************/

    mov rsp, [r14 + SS_OFFSET_RSP]

    /**************************************************************************/
    /* Debug Registers                                                        */
    /**************************************************************************/

    mov rax, dr0
    mov [r15 + SS_OFFSET_DR0], rax
    mov rax, [r14 + SS_OFFSET_DR0]
    mov dr0, rax

    mov rax, dr1
    mov [r15 + SS_OFFSET_DR1], rax
    mov rax, [r14 + SS_OFFSET_DR1]
    mov dr1, rax

    mov rax, dr2
    mov [r15 + SS_OFFSET_DR2], rax
    mov rax, [r14 + SS_OFFSET_DR2]
    mov dr2, rax

    mov rax, dr3
    mov [r15 + SS_OFFSET_DR3], rax
    mov rax, [r14 + SS_OFFSET_DR3]
    mov dr3, rax

    mov rax, dr6
    mov [r15 + SS_OFFSET_DR6], rax
    mov rax, [r14 + SS_OFFSET_DR6]
    mov dr6, rax

    mov rax, dr7
    mov [r15 + SS_OFFSET_DR7], rax
    mov rax, [r14 + SS_OFFSET_DR7]
    mov dr7, rax

    /**************************************************************************/
    /* Call Microkernel                                                       */
    /**************************************************************************/

    mov rdi, r13
    push qword ptr[r14 + SS_OFFSET_RIP]
    ret
    int 3

demotion_return:

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
