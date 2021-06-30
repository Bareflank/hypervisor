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
    #define TLS_OFFSET_CURRENT_FAST_FAIL_IP 0x290
    /** @brief defines the offset of tls_t.current_fast_fail_sp */
    #define TLS_OFFSET_CURRENT_FAST_FAIL_SP 0x298

    .text

    .globl  return_to_current_fast_fail
    .type   return_to_current_fast_fail, @function
return_to_current_fast_fail:

    mrs  x18, tpidr_el2

    add  x11, x18, #TLS_OFFSET_CURRENT_FAST_FAIL_SP
    ldr  x10, [x11]

    cbz  x10, use_current_stack
    mov  sp, x10
use_current_stack:

    add  x11, x18, #TLS_OFFSET_CURRENT_FAST_FAIL_IP
    ldr  x10, [x11]

    ret  x10

    .size return_to_current_fast_fail, .-return_to_current_fast_fail
