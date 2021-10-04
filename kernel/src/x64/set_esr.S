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

    .code64
    .intel_syntax noprefix

    .globl  set_esr
    .type   set_esr, @function
set_esr:

    /**
     * NOTE:
     * - The descriptors in the IDT are actually set up by the loader,
     *   and the only thing we need to actually do here is update the
     *   descriptors to use our handlers instead of the temporary
     *   handlers that the loader uses. So, step 1 is is to load the
     *   IDTR onto the stack so that we can fetch the descriptor that
     *   we plan to change.
     */

    push rax
    push ax
    sidt [rsp]
    pop ax
    pop rax

    /**
     * NOTE:
     * - Load RDI with the memory location of the descriptor that we
     *   want to change.
     */

    shl rdi, 4
    add rdi, rax

    /**
     * NOTE:
     * - Update Offset bits 0-15 in the descriptor with the new location
     *   of our ESR handler. If this doesn't make sense, please take a
     *   look at a Call-Gate Descriptor in Long Mode from the AMD manual
     *   as all of the information that is needed can be seen there.
     */

    mov rcx, [rdi]
    mov rax, 0xFFFFFFFFFFFF0000
    and rcx, rax
    mov rdx, rsi
    shl rdx, 0
    mov rax, 0x000000000000FFFF
    and rdx, rax
    or rcx, rdx
    mov [rdi], rcx

    /**
     * NOTE:
     * - Update Offset bits 31-16 in the descriptor with the new location
     *   of our ESR handler. If this doesn't make sense, please take a
     *   look at a Call-Gate Descriptor in Long Mode from the AMD manual
     *   as all of the information that is needed can be seen there.
     */

    mov rcx, [rdi]
    mov rax, 0x0000FFFFFFFFFFFF
    and rcx, rax
    mov rdx, rsi
    shl rdx, 32
    mov rax, 0xFFFF000000000000
    and rdx, rax
    or rcx, rdx
    mov [rdi], rcx

    /**
     * NOTE:
     * - Update Offset bits 63-32 in the descriptor with the new location
     *   of our ESR handler. If this doesn't make sense, please take a
     *   look at a Call-Gate Descriptor in Long Mode from the AMD manual
     *   as all of the information that is needed can be seen there.
     */

    mov rcx, [rdi + 8]
    mov rax, 0xFFFFFFFF00000000
    and rcx, rax
    mov rdx, rsi
    shr rdx, 32
    mov rax, 0x00000000FFFFFFFF
    and rdx, rax
    or rcx, rdx
    mov [rdi + 8], rcx

    ret
    int 3

    .size set_esr, .-set_esr
