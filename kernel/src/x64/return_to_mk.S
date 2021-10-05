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

    .code64
    .intel_syntax noprefix

    .globl  return_to_mk
    .type   return_to_mk, @function
return_to_mk:

    /**
     * NOTE:
     * - Restore the MK's SP
     */

    mov rsp, gs:[TLS_OFFSET_MK_SP]

    /**
     * NOTE:
     * - Restore the MK's state
     */

    mov r15, gs:[TLS_OFFSET_MK_R15]
    mov r14, gs:[TLS_OFFSET_MK_R14]
    mov r13, gs:[TLS_OFFSET_MK_R13]
    mov r12, gs:[TLS_OFFSET_MK_R12]
    mov rbp, gs:[TLS_OFFSET_MK_RBP]
    mov rbx, gs:[TLS_OFFSET_MK_RBX]

    mov rax, rdi
    ret
    int 3

    .size return_to_mk, .-return_to_mk
