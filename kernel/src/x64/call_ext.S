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
    /** @brief defines the offset of tls_t.mk_sp */
    #define TLS_OFFSET_MK_SP 0x180
    /** @brief defines the offset of tls_t.pp<> */
    #define TLS_OFFSET_PP_INFO 0x208
    /** @brief defines the offset of tls_t.active_<>id */
    #define TLS_OFFSET_ACTIVE_IDS 0x238

    /** @brief defines the rflags the extension will start with */
    #define EXT_RFLAGS 0x3002

    /** @brief defines the offset of the active ids in the ABI's TLS */
    #define ABI_TLS_ACTIVE_IDS 0xFF0
    /** @brief defines the offset of the PP info in the ABI's TLS */
    #define ABI_TLS_PP_INFO 0xFF8

    .code64
    .intel_syntax noprefix

    .globl  call_ext
    .type   call_ext, @function
call_ext:

    mov r10, rcx

    /**
     * NOTE:
     * - Save off the current MK state. Note that we do not need to worry
     *   about the volatile registers
     */

    mov gs:[TLS_OFFSET_MK_RBX], rbx
    mov gs:[TLS_OFFSET_MK_RBP], rbp
    mov gs:[TLS_OFFSET_MK_R12], r12
    mov gs:[TLS_OFFSET_MK_R13], r13
    mov gs:[TLS_OFFSET_MK_R14], r14
    mov gs:[TLS_OFFSET_MK_R15], r15

    /**
     * NOTE:
     * - Update the TLS ID information. This makes sure that each time the
     *   extension is called, it knows what the active resources are.
     *
     * TODO:
     * - This does not need to be done on every call. It should be moved
     *   to the set_active/set_inactive functions.
     */

    mov rax, gs:[TLS_OFFSET_ACTIVE_IDS]
    mov fs:[ABI_TLS_ACTIVE_IDS], rax
    mov rax, gs:[TLS_OFFSET_PP_INFO]
    mov fs:[ABI_TLS_PP_INFO], eax

    /**
     * NOTE:
     * - Update the stack to point to the stack that we have been told to
     *   use. Before we do this, we will save off the current SP of the
     *   MK so that when it is time to return from the extension, we have
     *   a proper SP.
     */

    mov gs:[TLS_OFFSET_MK_SP], rsp
    mov rsp, rsi

    /**
     * NOTE:
     * - Call the microkernel.
     */

    mov rcx, rdi
    mov r11, EXT_RFLAGS

    mov rdi, rdx
    mov rsi, r10

    xor rax, rax
    xor rbx, rbx
    xor rdx, rdx
    xor rbp, rbp
    xor r8, r8
    xor r9, r9
    xor r10, r10
    xor r12, r12
    xor r13, r13
    xor r14, r14
    xor r15, r15

    sysretq
    int 3

    .size call_ext, .-call_ext
