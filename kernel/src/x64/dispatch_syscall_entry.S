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

    /** @brief defines the offset of tls_t.ext_syscall */
    #define TLS_OFFSET_EXT_SYSCALL 0x030
    /** @brief defines the offset of tls_t.reserved_rbx */
    #define TLS_OFFSET_RESERVED_RBX 0x038
    /** @brief defines the offset of tls_t.reserved_rcx */
    #define TLS_OFFSET_RESERVED_RCX 0x040
    /** @brief defines the offset of tls_t.ext_reg2 */
    #define TLS_OFFSET_EXT_REG2 0x048
    /** @brief defines the offset of tls_t.reserved_rbp */
    #define TLS_OFFSET_RESERVED_RBP 0x050
    /** @brief defines the offset of tls_t.ext_reg1 */
    #define TLS_OFFSET_EXT_REG1 0x058
    /** @brief defines the offset of tls_t.ext_reg0 */
    #define TLS_OFFSET_EXT_REG0 0x060
    /** @brief defines the offset of tls_t.ext_reg4 */
    #define TLS_OFFSET_EXT_REG4 0x068
    /** @brief defines the offset of tls_t.ext_reg5 */
    #define TLS_OFFSET_EXT_REG5 0x070
    /** @brief defines the offset of tls_t.ext_reg3 */
    #define TLS_OFFSET_EXT_REG3 0x078
    /** @brief defines the offset of tls_t.reserved_r11 */
    #define TLS_OFFSET_RESERVED_R11 0x080
    /** @brief defines the offset of tls_t.reserved_r12 */
    #define TLS_OFFSET_RESERVED_R12 0x088
    /** @brief defines the offset of tls_t.reserved_r13 */
    #define TLS_OFFSET_RESERVED_R13 0x090
    /** @brief defines the offset of tls_t.reserved_r14 */
    #define TLS_OFFSET_RESERVED_R14 0x098
    /** @brief defines the offset of tls_t.reserved_r15 */
    #define TLS_OFFSET_RESERVED_R15 0x0A0
    /** @brief defines the offset of tls_t.ext_sp */
    #define TLS_OFFSET_EXT_SP 0x0A8

    /** @brief defines the offset of tls_t.mk_sp */
    #define TLS_OFFSET_MK_SP 0x180
    /** @brief defines the offset of tls_t.self */
    #define TLS_OFFSET_SELF 0x200
    /** @brief defines the offset of tls_t.pp<> */
    #define TLS_OFFSET_PP_INFO 0x208
    /** @brief defines the offset of tls_t.active_<>id */
    #define TLS_OFFSET_ACTIVE_IDS 0x238

    /** @brief defines the rflags the MK will start with */
    #define MK_RFLAGS 0x40002
    /** @brief defines the rflags the extension will start with */
    #define EXT_RFLAGS 0x3002

    /** @brief defines the offset of the active ids in the ABI's TLS */
    #define ABI_TLS_ACTIVE_IDS 0xFF0
    /** @brief defines the offset of the PP info in the ABI's TLS */
    #define ABI_TLS_PP_INFO 0xFF8


    .code64
    .intel_syntax noprefix

    .globl  dispatch_syscall_entry
    .type   dispatch_syscall_entry, @function
dispatch_syscall_entry:

    /**
     * NOTE:
     * - Save off the extension's registers. When we call from the microkernel
     *   to the extension, we only need to worry about the voliatile registers.
     *   Technical, this would be the case when we call from the extension to
     *   to the microkernel which is what this is doing, but in this case,
     *   if we do not save everything, we would end up leaking kernel state
     *   into the extension, which we do not want. Leaking extension state
     *   into the microkernel is fine.
     *
     * - Any register that is marked as "reserved" is just a safety thing to
     *   make sure that we do not accidentally use one of these registers in
     *   the code. Any register that is part of the ABI does not have an
     *   Intel name. Which registers are part of the ABI and which are not
     *   is based on SysV. Sadly, SysV uses RCX, which was reserved by AMD
     *   for the syscall instruction, so we replace RCX with R10, which means
     *   that the syscall assembly has to take this into account. Everything
     *   else matches SysV.
     */

    mov gs:[TLS_OFFSET_RESERVED_RCX], rcx
    mov gs:[TLS_OFFSET_RESERVED_R11], r11

    mov gs:[TLS_OFFSET_RESERVED_RBX], rbx
    mov gs:[TLS_OFFSET_RESERVED_RBP], rbp
    mov gs:[TLS_OFFSET_RESERVED_R12], r12
    mov gs:[TLS_OFFSET_RESERVED_R13], r13
    mov gs:[TLS_OFFSET_RESERVED_R14], r14
    mov gs:[TLS_OFFSET_RESERVED_R15], r15

    mov gs:[TLS_OFFSET_EXT_SYSCALL], rax
    mov gs:[TLS_OFFSET_EXT_REG0], rdi
    mov gs:[TLS_OFFSET_EXT_REG1], rsi
    mov gs:[TLS_OFFSET_EXT_REG2], rdx
    mov gs:[TLS_OFFSET_EXT_REG3], r10
    mov gs:[TLS_OFFSET_EXT_REG4], r8
    mov gs:[TLS_OFFSET_EXT_REG5], r9

    /**
     * NOTE:
     * - Save extension's current SP and load the MK's SP.
     */

    mov gs:[TLS_OFFSET_EXT_SP], rsp
    mov rsp, gs:[TLS_OFFSET_MK_SP]

    /**
     * NOTE:
     * - Set RFLAGS to the MK's starting RFLAGS value.
     */

    push MK_RFLAGS
    popf

    /**
     * NOTE:
     * - Run the syscall dispatch routine.
     */

    mov rdi, gs:[TLS_OFFSET_SELF]
    call dispatch_syscall_trampoline

    /**
     * NOTE:
     * - Now that we are back from the syscall handler, we need to update
     *   which resources are active. This is because the syscall handlers
     *   might have changed these values.
     *
     * TODO:
     * - This does not need to be done on every call. It should be moved
     *   to the set_active/set_inactive functions.
     */

    mov rdx, gs:[TLS_OFFSET_ACTIVE_IDS]
    mov fs:[ABI_TLS_ACTIVE_IDS], rdx
    mov edx, gs:[TLS_OFFSET_PP_INFO]
    mov fs:[ABI_TLS_PP_INFO], edx

    /**
     * NOTE:
     * - Restore the extension's SP
     */

    mov rsp, gs:[TLS_OFFSET_EXT_SP]

    /**
     * NOTE:
     * - Restore the extension's state before returning back to the
     *   extension. It should be noted that we do not touch RAX.
     *   this is so that the return value from the MK can be sent to
     *   the extension.
     */

    mov r9,  gs:[TLS_OFFSET_EXT_REG5]
    mov r8,  gs:[TLS_OFFSET_EXT_REG4]
    mov r10, gs:[TLS_OFFSET_EXT_REG3]
    mov rdx, gs:[TLS_OFFSET_EXT_REG2]
    mov rsi, gs:[TLS_OFFSET_EXT_REG1]
    mov rdi, gs:[TLS_OFFSET_EXT_REG0]

    mov r15, gs:[TLS_OFFSET_RESERVED_R15]
    mov r14, gs:[TLS_OFFSET_RESERVED_R14]
    mov r13, gs:[TLS_OFFSET_RESERVED_R13]
    mov r12, gs:[TLS_OFFSET_RESERVED_R12]
    mov rbp, gs:[TLS_OFFSET_RESERVED_RBP]
    mov rbx, gs:[TLS_OFFSET_RESERVED_RBX]

    mov r11, gs:[TLS_OFFSET_RESERVED_R11]
    mov rcx, gs:[TLS_OFFSET_RESERVED_RCX]

    sysretq
    int 3

    .size dispatch_syscall_entry, .-dispatch_syscall_entry
