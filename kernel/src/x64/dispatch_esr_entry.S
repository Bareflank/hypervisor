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

    /** @brief defines the offset of tls_t.mk_rbx */
    #define TLS_OFFSET_MK_RBX 0x000
    /** @brief defines the offset of tls_t.mk_rbp */
    #define TLS_OFFSET_MK_RBP 0x008
    /** @brief defines the offset of tls_t.mk_r12 */
    #define TLS_OFFSET_MK_R12 0x010
    /** @brief defines the offset of tls_t.mk_r13 */
    #define TLS_OFFSET_MK_R13 0x018
    /** @brief defines the offset of tls_t.mk_r14 */
    #define TLS_OFFSET_MK_R14 0x020
    /** @brief defines the offset of tls_t.mk_r15 */
    #define TLS_OFFSET_MK_R15 0x028

    /** @brief defines the offset of tls_t.esr_rax */
    #define TLS_OFFSET_ESR_RAX 0x0B0
    /** @brief defines the offset of tls_t.esr_rbx */
    #define TLS_OFFSET_ESR_RBX 0x0B8
    /** @brief defines the offset of tls_t.esr_rcx */
    #define TLS_OFFSET_ESR_RCX 0x0C0
    /** @brief defines the offset of tls_t.esr_rdx */
    #define TLS_OFFSET_ESR_RDX 0x0C8
    /** @brief defines the offset of tls_t.esr_rbp */
    #define TLS_OFFSET_ESR_RBP 0x0D0
    /** @brief defines the offset of tls_t.esr_rsi */
    #define TLS_OFFSET_ESR_RSI 0x0D8
    /** @brief defines the offset of tls_t.esr_rdi */
    #define TLS_OFFSET_ESR_RDI 0x0E0
    /** @brief defines the offset of tls_t.esr_r8 */
    #define TLS_OFFSET_ESR_R8 0x0E8
    /** @brief defines the offset of tls_t.esr_r9 */
    #define TLS_OFFSET_ESR_R9 0x0F0
    /** @brief defines the offset of tls_t.esr_r10 */
    #define TLS_OFFSET_ESR_R10 0x0F8
    /** @brief defines the offset of tls_t.esr_r11 */
    #define TLS_OFFSET_ESR_R11 0x100
    /** @brief defines the offset of tls_t.esr_r12 */
    #define TLS_OFFSET_ESR_R12 0x108
    /** @brief defines the offset of tls_t.esr_r13 */
    #define TLS_OFFSET_ESR_R13 0x110
    /** @brief defines the offset of tls_t.esr_r14 */
    #define TLS_OFFSET_ESR_R14 0x118
    /** @brief defines the offset of tls_t.esr_r15 */
    #define TLS_OFFSET_ESR_R15 0x120
    /** @brief defines the offset of tls_t.esr_ip */
    #define TLS_OFFSET_ESR_IP 0x128
    /** @brief defines the offset of tls_t.esr_rsp */
    #define TLS_OFFSET_ESR_RSP 0x130
    /** @brief defines the offset of tls_t.esr_vector */
    #define TLS_OFFSET_ESR_VECTOR 0x138
    /** @brief defines the offset of tls_t.esr_error_code */
    #define TLS_OFFSET_ESR_ERROR_CODE 0x140
    /** @brief defines the offset of tls_t.esr_cr0 */
    #define TLS_OFFSET_ESR_CR0 0x148
    /** @brief defines the offset of tls_t.esr_pf_addr */
    #define TLS_OFFSET_ESR_PF_ADDR 0x150
    /** @brief defines the offset of tls_t.esr_cr3 */
    #define TLS_OFFSET_ESR_CR3 0x158
    /** @brief defines the offset of tls_t.esr_cr4 */
    #define TLS_OFFSET_ESR_CR4 0x160
    /** @brief defines the offset of tls_t.esr_cs */
    #define TLS_OFFSET_ESR_CS 0x168
    /** @brief defines the offset of tls_t.esr_ss */
    #define TLS_OFFSET_ESR_SS 0x170
    /** @brief defines the offset of tls_t.esr_rflags */
    #define TLS_OFFSET_ESR_RFLAGS 0x178

    /** @brief defines the offset of tls_t.mk_sp */
    #define TLS_OFFSET_MK_SP 0x180
    /** @brief defines the offset of tls_t.mk_handling_esr */
    #define TLS_OFFSET_MK_HANDLING_ESR 0x188
    /** @brief defines the offset of tls_t.mk_fail_sp */
    #define TLS_OFFSET_MK_FAIL_SP 0x190
    /** @brief defines the offset of tls_t.self */
    #define TLS_OFFSET_SELF 0x200
    /** @brief defines the offset of tls_t.ppid */
    #define TLS_OFFSET_PPID 0x208
    /** @brief defines the offset of tls_t.active_<>id */
    #define TLS_OFFSET_ACTIVE_IDS 0x238

    /** @brief defines the rflags the MK will start with */
    #define MK_RFLAGS 0x40002

    .code64
    .intel_syntax noprefix

    .globl  dispatch_esr_entry
    .type   dispatch_esr_entry, @function
dispatch_esr_entry:

    /**
     * NOTE:
     * - Set the RFLAGs for the MK.
     */

    push MK_RFLAGS
    popf

    /**
     * NOTE:
     * - Save the current MK state. This is needed because if the fail handler
     *   in the extension decides to call a syscall, all of these values will
     *   be overridden, so we save them off here to make sure that the fail
     *   handler can do what it needs to.
     */

    push qword ptr gs:[TLS_OFFSET_MK_RBX]
    push qword ptr gs:[TLS_OFFSET_MK_RBP]
    push qword ptr gs:[TLS_OFFSET_MK_R12]
    push qword ptr gs:[TLS_OFFSET_MK_R13]
    push qword ptr gs:[TLS_OFFSET_MK_R14]
    push qword ptr gs:[TLS_OFFSET_MK_R15]

    /**
     * NOTE:
     * - For the same reason above, we also need to save the MK's SP.
     *   The difference here is that we save this to the TLS because
     *   the exception handler might need to restore this before
     *   returning here, so putting it on the stack will not work.
     */

    mov rdi, gs:[TLS_OFFSET_MK_SP]
    mov gs:[TLS_OFFSET_MK_FAIL_SP], rdi

    /**
     * NOTE:
     * - Call the ESR dispatch routine.
     */

    mov rdi, gs:[TLS_OFFSET_SELF]
    call dispatch_esr_trampoline

    /**
     * NOTE:
     * - Restore the MK SP which we saved above. See the comment above as
     *   to why we do this.
     */

    mov rdi, gs:[TLS_OFFSET_MK_FAIL_SP]
    mov gs:[TLS_OFFSET_MK_SP], rdi

    /**
     * NOTE:
     * - Restore the MK state. See the comment above as to why we do this.
     */

    pop qword ptr gs:[TLS_OFFSET_MK_R15]
    pop qword ptr gs:[TLS_OFFSET_MK_R14]
    pop qword ptr gs:[TLS_OFFSET_MK_R13]
    pop qword ptr gs:[TLS_OFFSET_MK_R12]
    pop qword ptr gs:[TLS_OFFSET_MK_RBP]
    pop qword ptr gs:[TLS_OFFSET_MK_RBX]

    /**
     * NOTE:
     * - The ESR dispatch routine keeps track of whether or not it has
     *   already been called. If it doesn't do that, you could end up
     *   with endless exceptions, crashes, etc... If we go this far, we
     *   are done, so we need to clear this flag.
     */

    mov rdi, 0x0
    mov gs:[TLS_OFFSET_MK_HANDLING_ESR], rdi

    /**
     * NOTE:
     * - If the ESR dispatch routine didn't return success, we need to
     *   halt the PP. Hopefully this never happens.
     */

    cmp rax, 0x0
    jne intrinsic_halt

    /**
     * NOTE:
     * - Return the ESR dispatch entry for the specific ESR vector that was
     *   called. This will restore state as needed.
     */

    ret
    int 3

    .size dispatch_esr_entry, .-dispatch_esr_entry

    /**************************************************************************/
    /* ESR Routines                                                           */
    /**************************************************************************/

    .globl  dispatch_esr_entry_0
    .type   dispatch_esr_entry_0, @function
dispatch_esr_entry_0:

    mov gs:[TLS_OFFSET_ESR_RAX], rax
    mov gs:[TLS_OFFSET_ESR_RBX], rbx
    mov gs:[TLS_OFFSET_ESR_RCX], rcx
    mov gs:[TLS_OFFSET_ESR_RDX], rdx
    mov gs:[TLS_OFFSET_ESR_RBP], rbp
    mov gs:[TLS_OFFSET_ESR_RSI], rsi
    mov gs:[TLS_OFFSET_ESR_RDI], rdi
    mov gs:[TLS_OFFSET_ESR_R8], r8
    mov gs:[TLS_OFFSET_ESR_R9], r9
    mov gs:[TLS_OFFSET_ESR_R10], r10
    mov gs:[TLS_OFFSET_ESR_R11], r11
    mov gs:[TLS_OFFSET_ESR_R12], r12
    mov gs:[TLS_OFFSET_ESR_R13], r13
    mov gs:[TLS_OFFSET_ESR_R14], r14
    mov gs:[TLS_OFFSET_ESR_R15], r15

    mov rax, [rsp + 0x00]
    mov gs:[TLS_OFFSET_ESR_IP], rax
    mov rax, [rsp + 0x18]
    mov gs:[TLS_OFFSET_ESR_RSP], rax

    mov rax, 0x0
    mov gs:[TLS_OFFSET_ESR_VECTOR], rax
    mov rax, 0x0
    mov gs:[TLS_OFFSET_ESR_ERROR_CODE], rax

    mov rax, cr0
    mov gs:[TLS_OFFSET_ESR_CR0], rax
    mov rax, cr2
    mov gs:[TLS_OFFSET_ESR_PF_ADDR], rax
    mov rax, cr3
    mov gs:[TLS_OFFSET_ESR_CR3], rax
    mov rax, cr4
    mov gs:[TLS_OFFSET_ESR_CR4], rax

    mov rax, [rsp + 0x08]
    mov gs:[TLS_OFFSET_ESR_CS], rax
    mov rax, [rsp + 0x20]
    mov gs:[TLS_OFFSET_ESR_SS], rax

    mov rax, [rsp + 0x10]
    mov gs:[TLS_OFFSET_ESR_RFLAGS], rax

    call dispatch_esr_entry

    mov r15, gs:[TLS_OFFSET_ESR_R15]
    mov r14, gs:[TLS_OFFSET_ESR_R14]
    mov r13, gs:[TLS_OFFSET_ESR_R13]
    mov r12, gs:[TLS_OFFSET_ESR_R12]
    mov r11, gs:[TLS_OFFSET_ESR_R11]
    mov r10, gs:[TLS_OFFSET_ESR_R10]
    mov r9,  gs:[TLS_OFFSET_ESR_R9]
    mov r8,  gs:[TLS_OFFSET_ESR_R8]
    mov rdi, gs:[TLS_OFFSET_ESR_RDI]
    mov rsi, gs:[TLS_OFFSET_ESR_RSI]
    mov rbp, gs:[TLS_OFFSET_ESR_RBP]
    mov rdx, gs:[TLS_OFFSET_ESR_RDX]
    mov rcx, gs:[TLS_OFFSET_ESR_RCX]
    mov rbx, gs:[TLS_OFFSET_ESR_RBX]
    mov rax, gs:[TLS_OFFSET_ESR_RAX]

    iretq
    int 3

    .size dispatch_esr_entry_0, .-dispatch_esr_entry_0



    .globl  dispatch_esr_entry_1
    .type   dispatch_esr_entry_1, @function
dispatch_esr_entry_1:

    mov gs:[TLS_OFFSET_ESR_RAX], rax
    mov gs:[TLS_OFFSET_ESR_RBX], rbx
    mov gs:[TLS_OFFSET_ESR_RCX], rcx
    mov gs:[TLS_OFFSET_ESR_RDX], rdx
    mov gs:[TLS_OFFSET_ESR_RBP], rbp
    mov gs:[TLS_OFFSET_ESR_RSI], rsi
    mov gs:[TLS_OFFSET_ESR_RDI], rdi
    mov gs:[TLS_OFFSET_ESR_R8], r8
    mov gs:[TLS_OFFSET_ESR_R9], r9
    mov gs:[TLS_OFFSET_ESR_R10], r10
    mov gs:[TLS_OFFSET_ESR_R11], r11
    mov gs:[TLS_OFFSET_ESR_R12], r12
    mov gs:[TLS_OFFSET_ESR_R13], r13
    mov gs:[TLS_OFFSET_ESR_R14], r14
    mov gs:[TLS_OFFSET_ESR_R15], r15

    mov rax, [rsp + 0x00]
    mov gs:[TLS_OFFSET_ESR_IP], rax
    mov rax, [rsp + 0x18]
    mov gs:[TLS_OFFSET_ESR_RSP], rax

    mov rax, 0x1
    mov gs:[TLS_OFFSET_ESR_VECTOR], rax
    mov rax, 0x0
    mov gs:[TLS_OFFSET_ESR_ERROR_CODE], rax

    mov rax, cr0
    mov gs:[TLS_OFFSET_ESR_CR0], rax
    mov rax, cr2
    mov gs:[TLS_OFFSET_ESR_PF_ADDR], rax
    mov rax, cr3
    mov gs:[TLS_OFFSET_ESR_CR3], rax
    mov rax, cr4
    mov gs:[TLS_OFFSET_ESR_CR4], rax

    mov rax, [rsp + 0x08]
    mov gs:[TLS_OFFSET_ESR_CS], rax
    mov rax, [rsp + 0x20]
    mov gs:[TLS_OFFSET_ESR_SS], rax

    mov rax, [rsp + 0x10]
    mov gs:[TLS_OFFSET_ESR_RFLAGS], rax

    call dispatch_esr_entry

    mov r15, gs:[TLS_OFFSET_ESR_R15]
    mov r14, gs:[TLS_OFFSET_ESR_R14]
    mov r13, gs:[TLS_OFFSET_ESR_R13]
    mov r12, gs:[TLS_OFFSET_ESR_R12]
    mov r11, gs:[TLS_OFFSET_ESR_R11]
    mov r10, gs:[TLS_OFFSET_ESR_R10]
    mov r9,  gs:[TLS_OFFSET_ESR_R9]
    mov r8,  gs:[TLS_OFFSET_ESR_R8]
    mov rdi, gs:[TLS_OFFSET_ESR_RDI]
    mov rsi, gs:[TLS_OFFSET_ESR_RSI]
    mov rbp, gs:[TLS_OFFSET_ESR_RBP]
    mov rdx, gs:[TLS_OFFSET_ESR_RDX]
    mov rcx, gs:[TLS_OFFSET_ESR_RCX]
    mov rbx, gs:[TLS_OFFSET_ESR_RBX]
    mov rax, gs:[TLS_OFFSET_ESR_RAX]

    iretq
    int 3

    .size dispatch_esr_entry_1, .-dispatch_esr_entry_1



    .globl  dispatch_esr_entry_2
    .type   dispatch_esr_entry_2, @function
dispatch_esr_entry_2:

    mov gs:[TLS_OFFSET_ESR_RAX], rax
    mov gs:[TLS_OFFSET_ESR_RBX], rbx
    mov gs:[TLS_OFFSET_ESR_RCX], rcx
    mov gs:[TLS_OFFSET_ESR_RDX], rdx
    mov gs:[TLS_OFFSET_ESR_RBP], rbp
    mov gs:[TLS_OFFSET_ESR_RSI], rsi
    mov gs:[TLS_OFFSET_ESR_RDI], rdi
    mov gs:[TLS_OFFSET_ESR_R8], r8
    mov gs:[TLS_OFFSET_ESR_R9], r9
    mov gs:[TLS_OFFSET_ESR_R10], r10
    mov gs:[TLS_OFFSET_ESR_R11], r11
    mov gs:[TLS_OFFSET_ESR_R12], r12
    mov gs:[TLS_OFFSET_ESR_R13], r13
    mov gs:[TLS_OFFSET_ESR_R14], r14
    mov gs:[TLS_OFFSET_ESR_R15], r15

    mov rax, [rsp + 0x00]
    mov gs:[TLS_OFFSET_ESR_IP], rax
    mov rax, [rsp + 0x18]
    mov gs:[TLS_OFFSET_ESR_RSP], rax

    mov rax, 0x2
    mov gs:[TLS_OFFSET_ESR_VECTOR], rax
    mov rax, 0x0
    mov gs:[TLS_OFFSET_ESR_ERROR_CODE], rax

    mov rax, cr0
    mov gs:[TLS_OFFSET_ESR_CR0], rax
    mov rax, cr2
    mov gs:[TLS_OFFSET_ESR_PF_ADDR], rax
    mov rax, cr3
    mov gs:[TLS_OFFSET_ESR_CR3], rax
    mov rax, cr4
    mov gs:[TLS_OFFSET_ESR_CR4], rax

    mov rax, [rsp + 0x08]
    mov gs:[TLS_OFFSET_ESR_CS], rax
    mov rax, [rsp + 0x20]
    mov gs:[TLS_OFFSET_ESR_SS], rax

    mov rax, [rsp + 0x10]
    mov gs:[TLS_OFFSET_ESR_RFLAGS], rax

    call dispatch_esr_entry

    mov r15, gs:[TLS_OFFSET_ESR_R15]
    mov r14, gs:[TLS_OFFSET_ESR_R14]
    mov r13, gs:[TLS_OFFSET_ESR_R13]
    mov r12, gs:[TLS_OFFSET_ESR_R12]
    mov r11, gs:[TLS_OFFSET_ESR_R11]
    mov r10, gs:[TLS_OFFSET_ESR_R10]
    mov r9,  gs:[TLS_OFFSET_ESR_R9]
    mov r8,  gs:[TLS_OFFSET_ESR_R8]
    mov rdi, gs:[TLS_OFFSET_ESR_RDI]
    mov rsi, gs:[TLS_OFFSET_ESR_RSI]
    mov rbp, gs:[TLS_OFFSET_ESR_RBP]
    mov rdx, gs:[TLS_OFFSET_ESR_RDX]
    mov rcx, gs:[TLS_OFFSET_ESR_RCX]
    mov rbx, gs:[TLS_OFFSET_ESR_RBX]
    mov rax, gs:[TLS_OFFSET_ESR_RAX]

    iretq
    int 3

    .size dispatch_esr_entry_2, .-dispatch_esr_entry_2



    .globl  dispatch_esr_entry_3
    .type   dispatch_esr_entry_3, @function
dispatch_esr_entry_3:

    mov gs:[TLS_OFFSET_ESR_RAX], rax
    mov gs:[TLS_OFFSET_ESR_RBX], rbx
    mov gs:[TLS_OFFSET_ESR_RCX], rcx
    mov gs:[TLS_OFFSET_ESR_RDX], rdx
    mov gs:[TLS_OFFSET_ESR_RBP], rbp
    mov gs:[TLS_OFFSET_ESR_RSI], rsi
    mov gs:[TLS_OFFSET_ESR_RDI], rdi
    mov gs:[TLS_OFFSET_ESR_R8], r8
    mov gs:[TLS_OFFSET_ESR_R9], r9
    mov gs:[TLS_OFFSET_ESR_R10], r10
    mov gs:[TLS_OFFSET_ESR_R11], r11
    mov gs:[TLS_OFFSET_ESR_R12], r12
    mov gs:[TLS_OFFSET_ESR_R13], r13
    mov gs:[TLS_OFFSET_ESR_R14], r14
    mov gs:[TLS_OFFSET_ESR_R15], r15

    mov rax, [rsp + 0x00]
    mov gs:[TLS_OFFSET_ESR_IP], rax
    mov rax, [rsp + 0x18]
    mov gs:[TLS_OFFSET_ESR_RSP], rax

    mov rax, 0x3
    mov gs:[TLS_OFFSET_ESR_VECTOR], rax
    mov rax, 0x0
    mov gs:[TLS_OFFSET_ESR_ERROR_CODE], rax

    mov rax, cr0
    mov gs:[TLS_OFFSET_ESR_CR0], rax
    mov rax, cr2
    mov gs:[TLS_OFFSET_ESR_PF_ADDR], rax
    mov rax, cr3
    mov gs:[TLS_OFFSET_ESR_CR3], rax
    mov rax, cr4
    mov gs:[TLS_OFFSET_ESR_CR4], rax

    mov rax, [rsp + 0x08]
    mov gs:[TLS_OFFSET_ESR_CS], rax
    mov rax, [rsp + 0x20]
    mov gs:[TLS_OFFSET_ESR_SS], rax

    mov rax, [rsp + 0x10]
    mov gs:[TLS_OFFSET_ESR_RFLAGS], rax

    call dispatch_esr_entry

    mov r15, gs:[TLS_OFFSET_ESR_R15]
    mov r14, gs:[TLS_OFFSET_ESR_R14]
    mov r13, gs:[TLS_OFFSET_ESR_R13]
    mov r12, gs:[TLS_OFFSET_ESR_R12]
    mov r11, gs:[TLS_OFFSET_ESR_R11]
    mov r10, gs:[TLS_OFFSET_ESR_R10]
    mov r9,  gs:[TLS_OFFSET_ESR_R9]
    mov r8,  gs:[TLS_OFFSET_ESR_R8]
    mov rdi, gs:[TLS_OFFSET_ESR_RDI]
    mov rsi, gs:[TLS_OFFSET_ESR_RSI]
    mov rbp, gs:[TLS_OFFSET_ESR_RBP]
    mov rdx, gs:[TLS_OFFSET_ESR_RDX]
    mov rcx, gs:[TLS_OFFSET_ESR_RCX]
    mov rbx, gs:[TLS_OFFSET_ESR_RBX]
    mov rax, gs:[TLS_OFFSET_ESR_RAX]

    iretq
    int 3

    .size dispatch_esr_entry_3, .-dispatch_esr_entry_3



    .globl  dispatch_esr_entry_4
    .type   dispatch_esr_entry_4, @function
dispatch_esr_entry_4:

    mov gs:[TLS_OFFSET_ESR_RAX], rax
    mov gs:[TLS_OFFSET_ESR_RBX], rbx
    mov gs:[TLS_OFFSET_ESR_RCX], rcx
    mov gs:[TLS_OFFSET_ESR_RDX], rdx
    mov gs:[TLS_OFFSET_ESR_RBP], rbp
    mov gs:[TLS_OFFSET_ESR_RSI], rsi
    mov gs:[TLS_OFFSET_ESR_RDI], rdi
    mov gs:[TLS_OFFSET_ESR_R8], r8
    mov gs:[TLS_OFFSET_ESR_R9], r9
    mov gs:[TLS_OFFSET_ESR_R10], r10
    mov gs:[TLS_OFFSET_ESR_R11], r11
    mov gs:[TLS_OFFSET_ESR_R12], r12
    mov gs:[TLS_OFFSET_ESR_R13], r13
    mov gs:[TLS_OFFSET_ESR_R14], r14
    mov gs:[TLS_OFFSET_ESR_R15], r15

    mov rax, [rsp + 0x00]
    mov gs:[TLS_OFFSET_ESR_IP], rax
    mov rax, [rsp + 0x18]
    mov gs:[TLS_OFFSET_ESR_RSP], rax

    mov rax, 0x4
    mov gs:[TLS_OFFSET_ESR_VECTOR], rax
    mov rax, 0x0
    mov gs:[TLS_OFFSET_ESR_ERROR_CODE], rax

    mov rax, cr0
    mov gs:[TLS_OFFSET_ESR_CR0], rax
    mov rax, cr2
    mov gs:[TLS_OFFSET_ESR_PF_ADDR], rax
    mov rax, cr3
    mov gs:[TLS_OFFSET_ESR_CR3], rax
    mov rax, cr4
    mov gs:[TLS_OFFSET_ESR_CR4], rax

    mov rax, [rsp + 0x08]
    mov gs:[TLS_OFFSET_ESR_CS], rax
    mov rax, [rsp + 0x20]
    mov gs:[TLS_OFFSET_ESR_SS], rax

    mov rax, [rsp + 0x10]
    mov gs:[TLS_OFFSET_ESR_RFLAGS], rax

    call dispatch_esr_entry

    mov r15, gs:[TLS_OFFSET_ESR_R15]
    mov r14, gs:[TLS_OFFSET_ESR_R14]
    mov r13, gs:[TLS_OFFSET_ESR_R13]
    mov r12, gs:[TLS_OFFSET_ESR_R12]
    mov r11, gs:[TLS_OFFSET_ESR_R11]
    mov r10, gs:[TLS_OFFSET_ESR_R10]
    mov r9,  gs:[TLS_OFFSET_ESR_R9]
    mov r8,  gs:[TLS_OFFSET_ESR_R8]
    mov rdi, gs:[TLS_OFFSET_ESR_RDI]
    mov rsi, gs:[TLS_OFFSET_ESR_RSI]
    mov rbp, gs:[TLS_OFFSET_ESR_RBP]
    mov rdx, gs:[TLS_OFFSET_ESR_RDX]
    mov rcx, gs:[TLS_OFFSET_ESR_RCX]
    mov rbx, gs:[TLS_OFFSET_ESR_RBX]
    mov rax, gs:[TLS_OFFSET_ESR_RAX]

    iretq
    int 3

    .size dispatch_esr_entry_4, .-dispatch_esr_entry_4



    .globl  dispatch_esr_entry_5
    .type   dispatch_esr_entry_5, @function
dispatch_esr_entry_5:

    mov gs:[TLS_OFFSET_ESR_RAX], rax
    mov gs:[TLS_OFFSET_ESR_RBX], rbx
    mov gs:[TLS_OFFSET_ESR_RCX], rcx
    mov gs:[TLS_OFFSET_ESR_RDX], rdx
    mov gs:[TLS_OFFSET_ESR_RBP], rbp
    mov gs:[TLS_OFFSET_ESR_RSI], rsi
    mov gs:[TLS_OFFSET_ESR_RDI], rdi
    mov gs:[TLS_OFFSET_ESR_R8], r8
    mov gs:[TLS_OFFSET_ESR_R9], r9
    mov gs:[TLS_OFFSET_ESR_R10], r10
    mov gs:[TLS_OFFSET_ESR_R11], r11
    mov gs:[TLS_OFFSET_ESR_R12], r12
    mov gs:[TLS_OFFSET_ESR_R13], r13
    mov gs:[TLS_OFFSET_ESR_R14], r14
    mov gs:[TLS_OFFSET_ESR_R15], r15

    mov rax, [rsp + 0x00]
    mov gs:[TLS_OFFSET_ESR_IP], rax
    mov rax, [rsp + 0x18]
    mov gs:[TLS_OFFSET_ESR_RSP], rax

    mov rax, 0x5
    mov gs:[TLS_OFFSET_ESR_VECTOR], rax
    mov rax, 0x0
    mov gs:[TLS_OFFSET_ESR_ERROR_CODE], rax

    mov rax, cr0
    mov gs:[TLS_OFFSET_ESR_CR0], rax
    mov rax, cr2
    mov gs:[TLS_OFFSET_ESR_PF_ADDR], rax
    mov rax, cr3
    mov gs:[TLS_OFFSET_ESR_CR3], rax
    mov rax, cr4
    mov gs:[TLS_OFFSET_ESR_CR4], rax

    mov rax, [rsp + 0x08]
    mov gs:[TLS_OFFSET_ESR_CS], rax
    mov rax, [rsp + 0x20]
    mov gs:[TLS_OFFSET_ESR_SS], rax

    mov rax, [rsp + 0x10]
    mov gs:[TLS_OFFSET_ESR_RFLAGS], rax

    call dispatch_esr_entry

    mov r15, gs:[TLS_OFFSET_ESR_R15]
    mov r14, gs:[TLS_OFFSET_ESR_R14]
    mov r13, gs:[TLS_OFFSET_ESR_R13]
    mov r12, gs:[TLS_OFFSET_ESR_R12]
    mov r11, gs:[TLS_OFFSET_ESR_R11]
    mov r10, gs:[TLS_OFFSET_ESR_R10]
    mov r9,  gs:[TLS_OFFSET_ESR_R9]
    mov r8,  gs:[TLS_OFFSET_ESR_R8]
    mov rdi, gs:[TLS_OFFSET_ESR_RDI]
    mov rsi, gs:[TLS_OFFSET_ESR_RSI]
    mov rbp, gs:[TLS_OFFSET_ESR_RBP]
    mov rdx, gs:[TLS_OFFSET_ESR_RDX]
    mov rcx, gs:[TLS_OFFSET_ESR_RCX]
    mov rbx, gs:[TLS_OFFSET_ESR_RBX]
    mov rax, gs:[TLS_OFFSET_ESR_RAX]

    iretq
    int 3

    .size dispatch_esr_entry_5, .-dispatch_esr_entry_5



    .globl  dispatch_esr_entry_6
    .type   dispatch_esr_entry_6, @function
dispatch_esr_entry_6:

    mov gs:[TLS_OFFSET_ESR_RAX], rax
    mov gs:[TLS_OFFSET_ESR_RBX], rbx
    mov gs:[TLS_OFFSET_ESR_RCX], rcx
    mov gs:[TLS_OFFSET_ESR_RDX], rdx
    mov gs:[TLS_OFFSET_ESR_RBP], rbp
    mov gs:[TLS_OFFSET_ESR_RSI], rsi
    mov gs:[TLS_OFFSET_ESR_RDI], rdi
    mov gs:[TLS_OFFSET_ESR_R8], r8
    mov gs:[TLS_OFFSET_ESR_R9], r9
    mov gs:[TLS_OFFSET_ESR_R10], r10
    mov gs:[TLS_OFFSET_ESR_R11], r11
    mov gs:[TLS_OFFSET_ESR_R12], r12
    mov gs:[TLS_OFFSET_ESR_R13], r13
    mov gs:[TLS_OFFSET_ESR_R14], r14
    mov gs:[TLS_OFFSET_ESR_R15], r15

    mov rax, [rsp + 0x00]
    mov gs:[TLS_OFFSET_ESR_IP], rax
    mov rax, [rsp + 0x18]
    mov gs:[TLS_OFFSET_ESR_RSP], rax

    mov rax, 0x6
    mov gs:[TLS_OFFSET_ESR_VECTOR], rax
    mov rax, 0x0
    mov gs:[TLS_OFFSET_ESR_ERROR_CODE], rax

    mov rax, cr0
    mov gs:[TLS_OFFSET_ESR_CR0], rax
    mov rax, cr2
    mov gs:[TLS_OFFSET_ESR_PF_ADDR], rax
    mov rax, cr3
    mov gs:[TLS_OFFSET_ESR_CR3], rax
    mov rax, cr4
    mov gs:[TLS_OFFSET_ESR_CR4], rax

    mov rax, [rsp + 0x08]
    mov gs:[TLS_OFFSET_ESR_CS], rax
    mov rax, [rsp + 0x20]
    mov gs:[TLS_OFFSET_ESR_SS], rax

    mov rax, [rsp + 0x10]
    mov gs:[TLS_OFFSET_ESR_RFLAGS], rax

    call dispatch_esr_entry

    mov r15, gs:[TLS_OFFSET_ESR_R15]
    mov r14, gs:[TLS_OFFSET_ESR_R14]
    mov r13, gs:[TLS_OFFSET_ESR_R13]
    mov r12, gs:[TLS_OFFSET_ESR_R12]
    mov r11, gs:[TLS_OFFSET_ESR_R11]
    mov r10, gs:[TLS_OFFSET_ESR_R10]
    mov r9,  gs:[TLS_OFFSET_ESR_R9]
    mov r8,  gs:[TLS_OFFSET_ESR_R8]
    mov rdi, gs:[TLS_OFFSET_ESR_RDI]
    mov rsi, gs:[TLS_OFFSET_ESR_RSI]
    mov rbp, gs:[TLS_OFFSET_ESR_RBP]
    mov rdx, gs:[TLS_OFFSET_ESR_RDX]
    mov rcx, gs:[TLS_OFFSET_ESR_RCX]
    mov rbx, gs:[TLS_OFFSET_ESR_RBX]
    mov rax, gs:[TLS_OFFSET_ESR_RAX]

    iretq
    int 3

    .size dispatch_esr_entry_6, .-dispatch_esr_entry_6



    .globl  dispatch_esr_entry_7
    .type   dispatch_esr_entry_7, @function
dispatch_esr_entry_7:

    mov gs:[TLS_OFFSET_ESR_RAX], rax
    mov gs:[TLS_OFFSET_ESR_RBX], rbx
    mov gs:[TLS_OFFSET_ESR_RCX], rcx
    mov gs:[TLS_OFFSET_ESR_RDX], rdx
    mov gs:[TLS_OFFSET_ESR_RBP], rbp
    mov gs:[TLS_OFFSET_ESR_RSI], rsi
    mov gs:[TLS_OFFSET_ESR_RDI], rdi
    mov gs:[TLS_OFFSET_ESR_R8], r8
    mov gs:[TLS_OFFSET_ESR_R9], r9
    mov gs:[TLS_OFFSET_ESR_R10], r10
    mov gs:[TLS_OFFSET_ESR_R11], r11
    mov gs:[TLS_OFFSET_ESR_R12], r12
    mov gs:[TLS_OFFSET_ESR_R13], r13
    mov gs:[TLS_OFFSET_ESR_R14], r14
    mov gs:[TLS_OFFSET_ESR_R15], r15

    mov rax, [rsp + 0x00]
    mov gs:[TLS_OFFSET_ESR_IP], rax
    mov rax, [rsp + 0x18]
    mov gs:[TLS_OFFSET_ESR_RSP], rax

    mov rax, 0x7
    mov gs:[TLS_OFFSET_ESR_VECTOR], rax
    mov rax, 0x0
    mov gs:[TLS_OFFSET_ESR_ERROR_CODE], rax

    mov rax, cr0
    mov gs:[TLS_OFFSET_ESR_CR0], rax
    mov rax, cr2
    mov gs:[TLS_OFFSET_ESR_PF_ADDR], rax
    mov rax, cr3
    mov gs:[TLS_OFFSET_ESR_CR3], rax
    mov rax, cr4
    mov gs:[TLS_OFFSET_ESR_CR4], rax

    mov rax, [rsp + 0x08]
    mov gs:[TLS_OFFSET_ESR_CS], rax
    mov rax, [rsp + 0x20]
    mov gs:[TLS_OFFSET_ESR_SS], rax

    mov rax, [rsp + 0x10]
    mov gs:[TLS_OFFSET_ESR_RFLAGS], rax

    call dispatch_esr_entry

    mov r15, gs:[TLS_OFFSET_ESR_R15]
    mov r14, gs:[TLS_OFFSET_ESR_R14]
    mov r13, gs:[TLS_OFFSET_ESR_R13]
    mov r12, gs:[TLS_OFFSET_ESR_R12]
    mov r11, gs:[TLS_OFFSET_ESR_R11]
    mov r10, gs:[TLS_OFFSET_ESR_R10]
    mov r9,  gs:[TLS_OFFSET_ESR_R9]
    mov r8,  gs:[TLS_OFFSET_ESR_R8]
    mov rdi, gs:[TLS_OFFSET_ESR_RDI]
    mov rsi, gs:[TLS_OFFSET_ESR_RSI]
    mov rbp, gs:[TLS_OFFSET_ESR_RBP]
    mov rdx, gs:[TLS_OFFSET_ESR_RDX]
    mov rcx, gs:[TLS_OFFSET_ESR_RCX]
    mov rbx, gs:[TLS_OFFSET_ESR_RBX]
    mov rax, gs:[TLS_OFFSET_ESR_RAX]

    iretq
    int 3

    .size dispatch_esr_entry_7, .-dispatch_esr_entry_7



    .globl  dispatch_esr_entry_8
    .type   dispatch_esr_entry_8, @function
dispatch_esr_entry_8:

    mov gs:[TLS_OFFSET_ESR_RAX], rax
    mov gs:[TLS_OFFSET_ESR_RBX], rbx
    mov gs:[TLS_OFFSET_ESR_RCX], rcx
    mov gs:[TLS_OFFSET_ESR_RDX], rdx
    mov gs:[TLS_OFFSET_ESR_RBP], rbp
    mov gs:[TLS_OFFSET_ESR_RSI], rsi
    mov gs:[TLS_OFFSET_ESR_RDI], rdi
    mov gs:[TLS_OFFSET_ESR_R8], r8
    mov gs:[TLS_OFFSET_ESR_R9], r9
    mov gs:[TLS_OFFSET_ESR_R10], r10
    mov gs:[TLS_OFFSET_ESR_R11], r11
    mov gs:[TLS_OFFSET_ESR_R12], r12
    mov gs:[TLS_OFFSET_ESR_R13], r13
    mov gs:[TLS_OFFSET_ESR_R14], r14
    mov gs:[TLS_OFFSET_ESR_R15], r15

    mov rax, [rsp + 0x08]
    mov gs:[TLS_OFFSET_ESR_IP], rax
    mov rax, [rsp + 0x20]
    mov gs:[TLS_OFFSET_ESR_RSP], rax

    mov rax, 0x8
    mov gs:[TLS_OFFSET_ESR_VECTOR], rax
    mov rax, [rsp + 0x00]
    mov gs:[TLS_OFFSET_ESR_ERROR_CODE], rax

    mov rax, cr0
    mov gs:[TLS_OFFSET_ESR_CR0], rax
    mov rax, cr2
    mov gs:[TLS_OFFSET_ESR_PF_ADDR], rax
    mov rax, cr3
    mov gs:[TLS_OFFSET_ESR_CR3], rax
    mov rax, cr4
    mov gs:[TLS_OFFSET_ESR_CR4], rax

    mov rax, [rsp + 0x10]
    mov gs:[TLS_OFFSET_ESR_CS], rax
    mov rax, [rsp + 0x28]
    mov gs:[TLS_OFFSET_ESR_SS], rax

    mov rax, [rsp + 0x18]
    mov gs:[TLS_OFFSET_ESR_RFLAGS], rax

    call dispatch_esr_entry

    pop rax

    mov r15, gs:[TLS_OFFSET_ESR_R15]
    mov r14, gs:[TLS_OFFSET_ESR_R14]
    mov r13, gs:[TLS_OFFSET_ESR_R13]
    mov r12, gs:[TLS_OFFSET_ESR_R12]
    mov r11, gs:[TLS_OFFSET_ESR_R11]
    mov r10, gs:[TLS_OFFSET_ESR_R10]
    mov r9,  gs:[TLS_OFFSET_ESR_R9]
    mov r8,  gs:[TLS_OFFSET_ESR_R8]
    mov rdi, gs:[TLS_OFFSET_ESR_RDI]
    mov rsi, gs:[TLS_OFFSET_ESR_RSI]
    mov rbp, gs:[TLS_OFFSET_ESR_RBP]
    mov rdx, gs:[TLS_OFFSET_ESR_RDX]
    mov rcx, gs:[TLS_OFFSET_ESR_RCX]
    mov rbx, gs:[TLS_OFFSET_ESR_RBX]
    mov rax, gs:[TLS_OFFSET_ESR_RAX]

    iretq
    int 3

    .size dispatch_esr_entry_8, .-dispatch_esr_entry_8



    .globl  dispatch_esr_entry_10
    .type   dispatch_esr_entry_10, @function
dispatch_esr_entry_10:

    mov gs:[TLS_OFFSET_ESR_RAX], rax
    mov gs:[TLS_OFFSET_ESR_RBX], rbx
    mov gs:[TLS_OFFSET_ESR_RCX], rcx
    mov gs:[TLS_OFFSET_ESR_RDX], rdx
    mov gs:[TLS_OFFSET_ESR_RBP], rbp
    mov gs:[TLS_OFFSET_ESR_RSI], rsi
    mov gs:[TLS_OFFSET_ESR_RDI], rdi
    mov gs:[TLS_OFFSET_ESR_R8], r8
    mov gs:[TLS_OFFSET_ESR_R9], r9
    mov gs:[TLS_OFFSET_ESR_R10], r10
    mov gs:[TLS_OFFSET_ESR_R11], r11
    mov gs:[TLS_OFFSET_ESR_R12], r12
    mov gs:[TLS_OFFSET_ESR_R13], r13
    mov gs:[TLS_OFFSET_ESR_R14], r14
    mov gs:[TLS_OFFSET_ESR_R15], r15

    mov rax, [rsp + 0x08]
    mov gs:[TLS_OFFSET_ESR_IP], rax
    mov rax, [rsp + 0x20]
    mov gs:[TLS_OFFSET_ESR_RSP], rax

    mov rax, 0xA
    mov gs:[TLS_OFFSET_ESR_VECTOR], rax
    mov rax, [rsp + 0x00]
    mov gs:[TLS_OFFSET_ESR_ERROR_CODE], rax

    mov rax, cr0
    mov gs:[TLS_OFFSET_ESR_CR0], rax
    mov rax, cr2
    mov gs:[TLS_OFFSET_ESR_PF_ADDR], rax
    mov rax, cr3
    mov gs:[TLS_OFFSET_ESR_CR3], rax
    mov rax, cr4
    mov gs:[TLS_OFFSET_ESR_CR4], rax

    mov rax, [rsp + 0x10]
    mov gs:[TLS_OFFSET_ESR_CS], rax
    mov rax, [rsp + 0x28]
    mov gs:[TLS_OFFSET_ESR_SS], rax

    mov rax, [rsp + 0x18]
    mov gs:[TLS_OFFSET_ESR_RFLAGS], rax

    call dispatch_esr_entry

    pop rax

    mov r15, gs:[TLS_OFFSET_ESR_R15]
    mov r14, gs:[TLS_OFFSET_ESR_R14]
    mov r13, gs:[TLS_OFFSET_ESR_R13]
    mov r12, gs:[TLS_OFFSET_ESR_R12]
    mov r11, gs:[TLS_OFFSET_ESR_R11]
    mov r10, gs:[TLS_OFFSET_ESR_R10]
    mov r9,  gs:[TLS_OFFSET_ESR_R9]
    mov r8,  gs:[TLS_OFFSET_ESR_R8]
    mov rdi, gs:[TLS_OFFSET_ESR_RDI]
    mov rsi, gs:[TLS_OFFSET_ESR_RSI]
    mov rbp, gs:[TLS_OFFSET_ESR_RBP]
    mov rdx, gs:[TLS_OFFSET_ESR_RDX]
    mov rcx, gs:[TLS_OFFSET_ESR_RCX]
    mov rbx, gs:[TLS_OFFSET_ESR_RBX]
    mov rax, gs:[TLS_OFFSET_ESR_RAX]

    iretq
    int 3

    .size dispatch_esr_entry_10, .-dispatch_esr_entry_10



    .globl  dispatch_esr_entry_11
    .type   dispatch_esr_entry_11, @function
dispatch_esr_entry_11:

    mov gs:[TLS_OFFSET_ESR_RAX], rax
    mov gs:[TLS_OFFSET_ESR_RBX], rbx
    mov gs:[TLS_OFFSET_ESR_RCX], rcx
    mov gs:[TLS_OFFSET_ESR_RDX], rdx
    mov gs:[TLS_OFFSET_ESR_RBP], rbp
    mov gs:[TLS_OFFSET_ESR_RSI], rsi
    mov gs:[TLS_OFFSET_ESR_RDI], rdi
    mov gs:[TLS_OFFSET_ESR_R8], r8
    mov gs:[TLS_OFFSET_ESR_R9], r9
    mov gs:[TLS_OFFSET_ESR_R10], r10
    mov gs:[TLS_OFFSET_ESR_R11], r11
    mov gs:[TLS_OFFSET_ESR_R12], r12
    mov gs:[TLS_OFFSET_ESR_R13], r13
    mov gs:[TLS_OFFSET_ESR_R14], r14
    mov gs:[TLS_OFFSET_ESR_R15], r15

    mov rax, [rsp + 0x08]
    mov gs:[TLS_OFFSET_ESR_IP], rax
    mov rax, [rsp + 0x20]
    mov gs:[TLS_OFFSET_ESR_RSP], rax

    mov rax, 0xB
    mov gs:[TLS_OFFSET_ESR_VECTOR], rax
    mov rax, [rsp + 0x00]
    mov gs:[TLS_OFFSET_ESR_ERROR_CODE], rax

    mov rax, cr0
    mov gs:[TLS_OFFSET_ESR_CR0], rax
    mov rax, cr2
    mov gs:[TLS_OFFSET_ESR_PF_ADDR], rax
    mov rax, cr3
    mov gs:[TLS_OFFSET_ESR_CR3], rax
    mov rax, cr4
    mov gs:[TLS_OFFSET_ESR_CR4], rax

    mov rax, [rsp + 0x10]
    mov gs:[TLS_OFFSET_ESR_CS], rax
    mov rax, [rsp + 0x28]
    mov gs:[TLS_OFFSET_ESR_SS], rax

    mov rax, [rsp + 0x18]
    mov gs:[TLS_OFFSET_ESR_RFLAGS], rax

    call dispatch_esr_entry

    pop rax

    mov r15, gs:[TLS_OFFSET_ESR_R15]
    mov r14, gs:[TLS_OFFSET_ESR_R14]
    mov r13, gs:[TLS_OFFSET_ESR_R13]
    mov r12, gs:[TLS_OFFSET_ESR_R12]
    mov r11, gs:[TLS_OFFSET_ESR_R11]
    mov r10, gs:[TLS_OFFSET_ESR_R10]
    mov r9,  gs:[TLS_OFFSET_ESR_R9]
    mov r8,  gs:[TLS_OFFSET_ESR_R8]
    mov rdi, gs:[TLS_OFFSET_ESR_RDI]
    mov rsi, gs:[TLS_OFFSET_ESR_RSI]
    mov rbp, gs:[TLS_OFFSET_ESR_RBP]
    mov rdx, gs:[TLS_OFFSET_ESR_RDX]
    mov rcx, gs:[TLS_OFFSET_ESR_RCX]
    mov rbx, gs:[TLS_OFFSET_ESR_RBX]
    mov rax, gs:[TLS_OFFSET_ESR_RAX]

    iretq
    int 3

    .size dispatch_esr_entry_11, .-dispatch_esr_entry_11



    .globl  dispatch_esr_entry_12
    .type   dispatch_esr_entry_12, @function
dispatch_esr_entry_12:

    mov gs:[TLS_OFFSET_ESR_RAX], rax
    mov gs:[TLS_OFFSET_ESR_RBX], rbx
    mov gs:[TLS_OFFSET_ESR_RCX], rcx
    mov gs:[TLS_OFFSET_ESR_RDX], rdx
    mov gs:[TLS_OFFSET_ESR_RBP], rbp
    mov gs:[TLS_OFFSET_ESR_RSI], rsi
    mov gs:[TLS_OFFSET_ESR_RDI], rdi
    mov gs:[TLS_OFFSET_ESR_R8], r8
    mov gs:[TLS_OFFSET_ESR_R9], r9
    mov gs:[TLS_OFFSET_ESR_R10], r10
    mov gs:[TLS_OFFSET_ESR_R11], r11
    mov gs:[TLS_OFFSET_ESR_R12], r12
    mov gs:[TLS_OFFSET_ESR_R13], r13
    mov gs:[TLS_OFFSET_ESR_R14], r14
    mov gs:[TLS_OFFSET_ESR_R15], r15

    mov rax, [rsp + 0x08]
    mov gs:[TLS_OFFSET_ESR_IP], rax
    mov rax, [rsp + 0x20]
    mov gs:[TLS_OFFSET_ESR_RSP], rax

    mov rax, 0xC
    mov gs:[TLS_OFFSET_ESR_VECTOR], rax
    mov rax, [rsp + 0x00]
    mov gs:[TLS_OFFSET_ESR_ERROR_CODE], rax

    mov rax, cr0
    mov gs:[TLS_OFFSET_ESR_CR0], rax
    mov rax, cr2
    mov gs:[TLS_OFFSET_ESR_PF_ADDR], rax
    mov rax, cr3
    mov gs:[TLS_OFFSET_ESR_CR3], rax
    mov rax, cr4
    mov gs:[TLS_OFFSET_ESR_CR4], rax

    mov rax, [rsp + 0x10]
    mov gs:[TLS_OFFSET_ESR_CS], rax
    mov rax, [rsp + 0x28]
    mov gs:[TLS_OFFSET_ESR_SS], rax

    mov rax, [rsp + 0x18]
    mov gs:[TLS_OFFSET_ESR_RFLAGS], rax

    call dispatch_esr_entry

    pop rax

    mov r15, gs:[TLS_OFFSET_ESR_R15]
    mov r14, gs:[TLS_OFFSET_ESR_R14]
    mov r13, gs:[TLS_OFFSET_ESR_R13]
    mov r12, gs:[TLS_OFFSET_ESR_R12]
    mov r11, gs:[TLS_OFFSET_ESR_R11]
    mov r10, gs:[TLS_OFFSET_ESR_R10]
    mov r9,  gs:[TLS_OFFSET_ESR_R9]
    mov r8,  gs:[TLS_OFFSET_ESR_R8]
    mov rdi, gs:[TLS_OFFSET_ESR_RDI]
    mov rsi, gs:[TLS_OFFSET_ESR_RSI]
    mov rbp, gs:[TLS_OFFSET_ESR_RBP]
    mov rdx, gs:[TLS_OFFSET_ESR_RDX]
    mov rcx, gs:[TLS_OFFSET_ESR_RCX]
    mov rbx, gs:[TLS_OFFSET_ESR_RBX]
    mov rax, gs:[TLS_OFFSET_ESR_RAX]

    iretq
    int 3

    .size dispatch_esr_entry_12, .-dispatch_esr_entry_12



    .globl  dispatch_esr_entry_13
    .type   dispatch_esr_entry_13, @function
dispatch_esr_entry_13:

    mov gs:[TLS_OFFSET_ESR_RAX], rax
    mov gs:[TLS_OFFSET_ESR_RBX], rbx
    mov gs:[TLS_OFFSET_ESR_RCX], rcx
    mov gs:[TLS_OFFSET_ESR_RDX], rdx
    mov gs:[TLS_OFFSET_ESR_RBP], rbp
    mov gs:[TLS_OFFSET_ESR_RSI], rsi
    mov gs:[TLS_OFFSET_ESR_RDI], rdi
    mov gs:[TLS_OFFSET_ESR_R8], r8
    mov gs:[TLS_OFFSET_ESR_R9], r9
    mov gs:[TLS_OFFSET_ESR_R10], r10
    mov gs:[TLS_OFFSET_ESR_R11], r11
    mov gs:[TLS_OFFSET_ESR_R12], r12
    mov gs:[TLS_OFFSET_ESR_R13], r13
    mov gs:[TLS_OFFSET_ESR_R14], r14
    mov gs:[TLS_OFFSET_ESR_R15], r15

    mov rax, gs:[0x250]
    cmp rax, 0x0
    jne dispatch_esr_entry_13_fix_rip

    mov rax, [rsp + 0x08]
    mov gs:[TLS_OFFSET_ESR_IP], rax
    mov rax, [rsp + 0x20]
    mov gs:[TLS_OFFSET_ESR_RSP], rax

    mov rax, 0xD
    mov gs:[TLS_OFFSET_ESR_VECTOR], rax
    mov rax, [rsp + 0x00]
    mov gs:[TLS_OFFSET_ESR_ERROR_CODE], rax

    mov rax, cr0
    mov gs:[TLS_OFFSET_ESR_CR0], rax
    mov rax, cr2
    mov gs:[TLS_OFFSET_ESR_PF_ADDR], rax
    mov rax, cr3
    mov gs:[TLS_OFFSET_ESR_CR3], rax
    mov rax, cr4
    mov gs:[TLS_OFFSET_ESR_CR4], rax

    mov rax, [rsp + 0x10]
    mov gs:[TLS_OFFSET_ESR_CS], rax
    mov rax, [rsp + 0x28]
    mov gs:[TLS_OFFSET_ESR_SS], rax

    mov rax, [rsp + 0x18]
    mov gs:[TLS_OFFSET_ESR_RFLAGS], rax

    call dispatch_esr_entry

dispatch_esr_entry_13_ret:

    pop rax

    mov r15, gs:[TLS_OFFSET_ESR_R15]
    mov r14, gs:[TLS_OFFSET_ESR_R14]
    mov r13, gs:[TLS_OFFSET_ESR_R13]
    mov r12, gs:[TLS_OFFSET_ESR_R12]
    mov r11, gs:[TLS_OFFSET_ESR_R11]
    mov r10, gs:[TLS_OFFSET_ESR_R10]
    mov r9,  gs:[TLS_OFFSET_ESR_R9]
    mov r8,  gs:[TLS_OFFSET_ESR_R8]
    mov rdi, gs:[TLS_OFFSET_ESR_RDI]
    mov rsi, gs:[TLS_OFFSET_ESR_RSI]
    mov rbp, gs:[TLS_OFFSET_ESR_RBP]
    mov rdx, gs:[TLS_OFFSET_ESR_RDX]
    mov rcx, gs:[TLS_OFFSET_ESR_RCX]
    mov rbx, gs:[TLS_OFFSET_ESR_RBX]
    mov rax, gs:[TLS_OFFSET_ESR_RAX]

    iretq
    int 3

dispatch_esr_entry_13_fix_rip:
    mov [rsp + 0x08], rax
    jmp dispatch_esr_entry_13_ret

    .size dispatch_esr_entry_13, .-dispatch_esr_entry_13



    .globl  dispatch_esr_entry_14
    .type   dispatch_esr_entry_14, @function
dispatch_esr_entry_14:

    mov gs:[TLS_OFFSET_ESR_RAX], rax
    mov gs:[TLS_OFFSET_ESR_RBX], rbx
    mov gs:[TLS_OFFSET_ESR_RCX], rcx
    mov gs:[TLS_OFFSET_ESR_RDX], rdx
    mov gs:[TLS_OFFSET_ESR_RBP], rbp
    mov gs:[TLS_OFFSET_ESR_RSI], rsi
    mov gs:[TLS_OFFSET_ESR_RDI], rdi
    mov gs:[TLS_OFFSET_ESR_R8], r8
    mov gs:[TLS_OFFSET_ESR_R9], r9
    mov gs:[TLS_OFFSET_ESR_R10], r10
    mov gs:[TLS_OFFSET_ESR_R11], r11
    mov gs:[TLS_OFFSET_ESR_R12], r12
    mov gs:[TLS_OFFSET_ESR_R13], r13
    mov gs:[TLS_OFFSET_ESR_R14], r14
    mov gs:[TLS_OFFSET_ESR_R15], r15

    mov rax, [rsp + 0x08]
    mov gs:[TLS_OFFSET_ESR_IP], rax
    mov rax, [rsp + 0x20]
    mov gs:[TLS_OFFSET_ESR_RSP], rax

    mov rax, 0xE
    mov gs:[TLS_OFFSET_ESR_VECTOR], rax
    mov rax, [rsp + 0x00]
    mov gs:[TLS_OFFSET_ESR_ERROR_CODE], rax

    mov rax, cr0
    mov gs:[TLS_OFFSET_ESR_CR0], rax
    mov rax, cr2
    mov gs:[TLS_OFFSET_ESR_PF_ADDR], rax
    mov rax, cr3
    mov gs:[TLS_OFFSET_ESR_CR3], rax
    mov rax, cr4
    mov gs:[TLS_OFFSET_ESR_CR4], rax

    mov rax, [rsp + 0x10]
    mov gs:[TLS_OFFSET_ESR_CS], rax
    mov rax, [rsp + 0x28]
    mov gs:[TLS_OFFSET_ESR_SS], rax

    mov rax, [rsp + 0x18]
    mov gs:[TLS_OFFSET_ESR_RFLAGS], rax

    mov rax, 0x0
    mov cr2, rax

    call dispatch_esr_entry

    pop rax

    mov r15, gs:[TLS_OFFSET_ESR_R15]
    mov r14, gs:[TLS_OFFSET_ESR_R14]
    mov r13, gs:[TLS_OFFSET_ESR_R13]
    mov r12, gs:[TLS_OFFSET_ESR_R12]
    mov r11, gs:[TLS_OFFSET_ESR_R11]
    mov r10, gs:[TLS_OFFSET_ESR_R10]
    mov r9,  gs:[TLS_OFFSET_ESR_R9]
    mov r8,  gs:[TLS_OFFSET_ESR_R8]
    mov rdi, gs:[TLS_OFFSET_ESR_RDI]
    mov rsi, gs:[TLS_OFFSET_ESR_RSI]
    mov rbp, gs:[TLS_OFFSET_ESR_RBP]
    mov rdx, gs:[TLS_OFFSET_ESR_RDX]
    mov rcx, gs:[TLS_OFFSET_ESR_RCX]
    mov rbx, gs:[TLS_OFFSET_ESR_RBX]
    mov rax, gs:[TLS_OFFSET_ESR_RAX]

    iretq
    int 3

    .size dispatch_esr_entry_14, .-dispatch_esr_entry_14



    .globl  dispatch_esr_entry_16
    .type   dispatch_esr_entry_16, @function
dispatch_esr_entry_16:

    mov gs:[TLS_OFFSET_ESR_RAX], rax
    mov gs:[TLS_OFFSET_ESR_RBX], rbx
    mov gs:[TLS_OFFSET_ESR_RCX], rcx
    mov gs:[TLS_OFFSET_ESR_RDX], rdx
    mov gs:[TLS_OFFSET_ESR_RBP], rbp
    mov gs:[TLS_OFFSET_ESR_RSI], rsi
    mov gs:[TLS_OFFSET_ESR_RDI], rdi
    mov gs:[TLS_OFFSET_ESR_R8], r8
    mov gs:[TLS_OFFSET_ESR_R9], r9
    mov gs:[TLS_OFFSET_ESR_R10], r10
    mov gs:[TLS_OFFSET_ESR_R11], r11
    mov gs:[TLS_OFFSET_ESR_R12], r12
    mov gs:[TLS_OFFSET_ESR_R13], r13
    mov gs:[TLS_OFFSET_ESR_R14], r14
    mov gs:[TLS_OFFSET_ESR_R15], r15

    mov rax, [rsp + 0x00]
    mov gs:[TLS_OFFSET_ESR_IP], rax
    mov rax, [rsp + 0x18]
    mov gs:[TLS_OFFSET_ESR_RSP], rax

    mov rax, 0x10
    mov gs:[TLS_OFFSET_ESR_VECTOR], rax
    mov rax, 0x0
    mov gs:[TLS_OFFSET_ESR_ERROR_CODE], rax

    mov rax, cr0
    mov gs:[TLS_OFFSET_ESR_CR0], rax
    mov rax, cr2
    mov gs:[TLS_OFFSET_ESR_PF_ADDR], rax
    mov rax, cr3
    mov gs:[TLS_OFFSET_ESR_CR3], rax
    mov rax, cr4
    mov gs:[TLS_OFFSET_ESR_CR4], rax

    mov rax, [rsp + 0x08]
    mov gs:[TLS_OFFSET_ESR_CS], rax
    mov rax, [rsp + 0x20]
    mov gs:[TLS_OFFSET_ESR_SS], rax

    mov rax, [rsp + 0x10]
    mov gs:[TLS_OFFSET_ESR_RFLAGS], rax

    call dispatch_esr_entry

    mov r15, gs:[TLS_OFFSET_ESR_R15]
    mov r14, gs:[TLS_OFFSET_ESR_R14]
    mov r13, gs:[TLS_OFFSET_ESR_R13]
    mov r12, gs:[TLS_OFFSET_ESR_R12]
    mov r11, gs:[TLS_OFFSET_ESR_R11]
    mov r10, gs:[TLS_OFFSET_ESR_R10]
    mov r9,  gs:[TLS_OFFSET_ESR_R9]
    mov r8,  gs:[TLS_OFFSET_ESR_R8]
    mov rdi, gs:[TLS_OFFSET_ESR_RDI]
    mov rsi, gs:[TLS_OFFSET_ESR_RSI]
    mov rbp, gs:[TLS_OFFSET_ESR_RBP]
    mov rdx, gs:[TLS_OFFSET_ESR_RDX]
    mov rcx, gs:[TLS_OFFSET_ESR_RCX]
    mov rbx, gs:[TLS_OFFSET_ESR_RBX]
    mov rax, gs:[TLS_OFFSET_ESR_RAX]

    iretq
    int 3

    .size dispatch_esr_entry_16, .-dispatch_esr_entry_16



    .globl  dispatch_esr_entry_17
    .type   dispatch_esr_entry_17, @function
dispatch_esr_entry_17:

    mov gs:[TLS_OFFSET_ESR_RAX], rax
    mov gs:[TLS_OFFSET_ESR_RBX], rbx
    mov gs:[TLS_OFFSET_ESR_RCX], rcx
    mov gs:[TLS_OFFSET_ESR_RDX], rdx
    mov gs:[TLS_OFFSET_ESR_RBP], rbp
    mov gs:[TLS_OFFSET_ESR_RSI], rsi
    mov gs:[TLS_OFFSET_ESR_RDI], rdi
    mov gs:[TLS_OFFSET_ESR_R8], r8
    mov gs:[TLS_OFFSET_ESR_R9], r9
    mov gs:[TLS_OFFSET_ESR_R10], r10
    mov gs:[TLS_OFFSET_ESR_R11], r11
    mov gs:[TLS_OFFSET_ESR_R12], r12
    mov gs:[TLS_OFFSET_ESR_R13], r13
    mov gs:[TLS_OFFSET_ESR_R14], r14
    mov gs:[TLS_OFFSET_ESR_R15], r15

    mov rax, [rsp + 0x08]
    mov gs:[TLS_OFFSET_ESR_IP], rax
    mov rax, [rsp + 0x20]
    mov gs:[TLS_OFFSET_ESR_RSP], rax

    mov rax, 0x11
    mov gs:[TLS_OFFSET_ESR_VECTOR], rax
    mov rax, [rsp + 0x00]
    mov gs:[TLS_OFFSET_ESR_ERROR_CODE], rax

    mov rax, cr0
    mov gs:[TLS_OFFSET_ESR_CR0], rax
    mov rax, cr2
    mov gs:[TLS_OFFSET_ESR_PF_ADDR], rax
    mov rax, cr3
    mov gs:[TLS_OFFSET_ESR_CR3], rax
    mov rax, cr4
    mov gs:[TLS_OFFSET_ESR_CR4], rax

    mov rax, [rsp + 0x10]
    mov gs:[TLS_OFFSET_ESR_CS], rax
    mov rax, [rsp + 0x28]
    mov gs:[TLS_OFFSET_ESR_SS], rax

    mov rax, [rsp + 0x18]
    mov gs:[TLS_OFFSET_ESR_RFLAGS], rax

    call dispatch_esr_entry

    pop rax

    mov r15, gs:[TLS_OFFSET_ESR_R15]
    mov r14, gs:[TLS_OFFSET_ESR_R14]
    mov r13, gs:[TLS_OFFSET_ESR_R13]
    mov r12, gs:[TLS_OFFSET_ESR_R12]
    mov r11, gs:[TLS_OFFSET_ESR_R11]
    mov r10, gs:[TLS_OFFSET_ESR_R10]
    mov r9,  gs:[TLS_OFFSET_ESR_R9]
    mov r8,  gs:[TLS_OFFSET_ESR_R8]
    mov rdi, gs:[TLS_OFFSET_ESR_RDI]
    mov rsi, gs:[TLS_OFFSET_ESR_RSI]
    mov rbp, gs:[TLS_OFFSET_ESR_RBP]
    mov rdx, gs:[TLS_OFFSET_ESR_RDX]
    mov rcx, gs:[TLS_OFFSET_ESR_RCX]
    mov rbx, gs:[TLS_OFFSET_ESR_RBX]
    mov rax, gs:[TLS_OFFSET_ESR_RAX]

    iretq
    int 3

    .size dispatch_esr_entry_17, .-dispatch_esr_entry_17



    .globl  dispatch_esr_entry_18
    .type   dispatch_esr_entry_18, @function
dispatch_esr_entry_18:

    mov gs:[TLS_OFFSET_ESR_RAX], rax
    mov gs:[TLS_OFFSET_ESR_RBX], rbx
    mov gs:[TLS_OFFSET_ESR_RCX], rcx
    mov gs:[TLS_OFFSET_ESR_RDX], rdx
    mov gs:[TLS_OFFSET_ESR_RBP], rbp
    mov gs:[TLS_OFFSET_ESR_RSI], rsi
    mov gs:[TLS_OFFSET_ESR_RDI], rdi
    mov gs:[TLS_OFFSET_ESR_R8], r8
    mov gs:[TLS_OFFSET_ESR_R9], r9
    mov gs:[TLS_OFFSET_ESR_R10], r10
    mov gs:[TLS_OFFSET_ESR_R11], r11
    mov gs:[TLS_OFFSET_ESR_R12], r12
    mov gs:[TLS_OFFSET_ESR_R13], r13
    mov gs:[TLS_OFFSET_ESR_R14], r14
    mov gs:[TLS_OFFSET_ESR_R15], r15

    mov rax, [rsp + 0x00]
    mov gs:[TLS_OFFSET_ESR_IP], rax
    mov rax, [rsp + 0x18]
    mov gs:[TLS_OFFSET_ESR_RSP], rax

    mov rax, 0x12
    mov gs:[TLS_OFFSET_ESR_VECTOR], rax
    mov rax, 0x0
    mov gs:[TLS_OFFSET_ESR_ERROR_CODE], rax

    mov rax, cr0
    mov gs:[TLS_OFFSET_ESR_CR0], rax
    mov rax, cr2
    mov gs:[TLS_OFFSET_ESR_PF_ADDR], rax
    mov rax, cr3
    mov gs:[TLS_OFFSET_ESR_CR3], rax
    mov rax, cr4
    mov gs:[TLS_OFFSET_ESR_CR4], rax

    mov rax, [rsp + 0x08]
    mov gs:[TLS_OFFSET_ESR_CS], rax
    mov rax, [rsp + 0x20]
    mov gs:[TLS_OFFSET_ESR_SS], rax

    mov rax, [rsp + 0x10]
    mov gs:[TLS_OFFSET_ESR_RFLAGS], rax

    call dispatch_esr_entry

    mov r15, gs:[TLS_OFFSET_ESR_R15]
    mov r14, gs:[TLS_OFFSET_ESR_R14]
    mov r13, gs:[TLS_OFFSET_ESR_R13]
    mov r12, gs:[TLS_OFFSET_ESR_R12]
    mov r11, gs:[TLS_OFFSET_ESR_R11]
    mov r10, gs:[TLS_OFFSET_ESR_R10]
    mov r9,  gs:[TLS_OFFSET_ESR_R9]
    mov r8,  gs:[TLS_OFFSET_ESR_R8]
    mov rdi, gs:[TLS_OFFSET_ESR_RDI]
    mov rsi, gs:[TLS_OFFSET_ESR_RSI]
    mov rbp, gs:[TLS_OFFSET_ESR_RBP]
    mov rdx, gs:[TLS_OFFSET_ESR_RDX]
    mov rcx, gs:[TLS_OFFSET_ESR_RCX]
    mov rbx, gs:[TLS_OFFSET_ESR_RBX]
    mov rax, gs:[TLS_OFFSET_ESR_RAX]

    iretq
    int 3

    .size dispatch_esr_entry_18, .-dispatch_esr_entry_18



    .globl  dispatch_esr_entry_19
    .type   dispatch_esr_entry_19, @function
dispatch_esr_entry_19:

    mov gs:[TLS_OFFSET_ESR_RAX], rax
    mov gs:[TLS_OFFSET_ESR_RBX], rbx
    mov gs:[TLS_OFFSET_ESR_RCX], rcx
    mov gs:[TLS_OFFSET_ESR_RDX], rdx
    mov gs:[TLS_OFFSET_ESR_RBP], rbp
    mov gs:[TLS_OFFSET_ESR_RSI], rsi
    mov gs:[TLS_OFFSET_ESR_RDI], rdi
    mov gs:[TLS_OFFSET_ESR_R8], r8
    mov gs:[TLS_OFFSET_ESR_R9], r9
    mov gs:[TLS_OFFSET_ESR_R10], r10
    mov gs:[TLS_OFFSET_ESR_R11], r11
    mov gs:[TLS_OFFSET_ESR_R12], r12
    mov gs:[TLS_OFFSET_ESR_R13], r13
    mov gs:[TLS_OFFSET_ESR_R14], r14
    mov gs:[TLS_OFFSET_ESR_R15], r15

    mov rax, [rsp + 0x00]
    mov gs:[TLS_OFFSET_ESR_IP], rax
    mov rax, [rsp + 0x18]
    mov gs:[TLS_OFFSET_ESR_RSP], rax

    mov rax, 0x13
    mov gs:[TLS_OFFSET_ESR_VECTOR], rax
    mov rax, 0x0
    mov gs:[TLS_OFFSET_ESR_ERROR_CODE], rax

    mov rax, cr0
    mov gs:[TLS_OFFSET_ESR_CR0], rax
    mov rax, cr2
    mov gs:[TLS_OFFSET_ESR_PF_ADDR], rax
    mov rax, cr3
    mov gs:[TLS_OFFSET_ESR_CR3], rax
    mov rax, cr4
    mov gs:[TLS_OFFSET_ESR_CR4], rax

    mov rax, [rsp + 0x08]
    mov gs:[TLS_OFFSET_ESR_CS], rax
    mov rax, [rsp + 0x20]
    mov gs:[TLS_OFFSET_ESR_SS], rax

    mov rax, [rsp + 0x10]
    mov gs:[TLS_OFFSET_ESR_RFLAGS], rax

    call dispatch_esr_entry

    mov r15, gs:[TLS_OFFSET_ESR_R15]
    mov r14, gs:[TLS_OFFSET_ESR_R14]
    mov r13, gs:[TLS_OFFSET_ESR_R13]
    mov r12, gs:[TLS_OFFSET_ESR_R12]
    mov r11, gs:[TLS_OFFSET_ESR_R11]
    mov r10, gs:[TLS_OFFSET_ESR_R10]
    mov r9,  gs:[TLS_OFFSET_ESR_R9]
    mov r8,  gs:[TLS_OFFSET_ESR_R8]
    mov rdi, gs:[TLS_OFFSET_ESR_RDI]
    mov rsi, gs:[TLS_OFFSET_ESR_RSI]
    mov rbp, gs:[TLS_OFFSET_ESR_RBP]
    mov rdx, gs:[TLS_OFFSET_ESR_RDX]
    mov rcx, gs:[TLS_OFFSET_ESR_RCX]
    mov rbx, gs:[TLS_OFFSET_ESR_RBX]
    mov rax, gs:[TLS_OFFSET_ESR_RAX]

    iretq
    int 3

    .size dispatch_esr_entry_19, .-dispatch_esr_entry_19
