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

    /** @brief defines the offset of tls_t.current_fast_fail_ip */
    #define TLS_OFFSET_CURRENT_FAST_FAIL_IP 0x180
    /** @brief defines the offset of tls_t.current_fast_fail_sp */
    #define TLS_OFFSET_CURRENT_FAST_FAIL_SP 0x188

    .code64
    .intel_syntax noprefix

    .globl  return_to_current_fast_fail
    .type   return_to_current_fast_fail, @function
return_to_current_fast_fail:

    mov rax, gs:[TLS_OFFSET_CURRENT_FAST_FAIL_SP]

    cmp rax, 0
    je use_current_stack
    mov rsp, rax
use_current_stack:

    call set_up_target
capture_spec:
    pause
    jmp capture_spec
set_up_target:
    mov rax, gs:[TLS_OFFSET_CURRENT_FAST_FAIL_IP]
    mov [rsp], rax
    ret
    int 3

    .size return_to_current_fast_fail, .-return_to_current_fast_fail
