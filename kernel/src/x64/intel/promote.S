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

    .globl  promote
    .type   promote, @function
promote:

    mov r15, rdi
    mov [r15 + 0x000], rsi

    mov rdi, 0
    mov rsi, [r15 + 0x2F0]
    call set_esr

    mov rdi, 1
    mov rsi, [r15 + 0x2F0]
    call set_esr

    mov rdi, 2
    mov rsi, [r15 + 0x308]
    call set_esr

    mov rdi, 3
    mov rsi, [r15 + 0x2F0]
    call set_esr

    mov rdi, 4
    mov rsi, [r15 + 0x2F0]
    call set_esr

    mov rdi, 5
    mov rsi, [r15 + 0x2F0]
    call set_esr

    mov rdi, 6
    mov rsi, [r15 + 0x2F0]
    call set_esr

    mov rdi, 7
    mov rsi, [r15 + 0x2F0]
    call set_esr

    mov rdi, 8
    mov rsi, [r15 + 0x2F8]
    call set_esr

    mov rdi, 10
    mov rsi, [r15 + 0x2F0]
    call set_esr

    mov rdi, 11
    mov rsi, [r15 + 0x2F0]
    call set_esr

    mov rdi, 12
    mov rsi, [r15 + 0x2F0]
    call set_esr

    mov rdi, 13
    mov rsi, [r15 + 0x300]
    call set_esr

    mov rdi, 14
    mov rsi, [r15 + 0x310]
    call set_esr

    mov rdi, 16
    mov rsi, [r15 + 0x2F0]
    call set_esr

    mov rdi, 17
    mov rsi, [r15 + 0x2F0]
    call set_esr

    mov rdi, 18
    mov rsi, [r15 + 0x2F0]
    call set_esr

    mov rdi, 19
    mov rsi, [r15 + 0x2F0]
    call set_esr

    /**
     * NOTE:
     * - Once the loader's ESRs are installed into the IDT, we need to
     *   determine if an NMI has fired. If it has, we need to tell the
     *   loader's promote logic so that it can inject an NMI once
     *   the promote process is complete.
     * - There are two different ways an NMI could be recorded. The first
     *   is the NMI pending bit, which means that an NMI occured while
     *   the hypervisor was executing, or the NMI window in the VMCS,
     *   which means the hypevisor was about to inject but never got a
     *   chance.
     */

    /**
     * TODO:
     * - There is a third was an NMI could be recorded. If an extension
     *   injects an NMI and then promotes without ever allowing the
     *   injection to process. For now we don't handle this case as it
     *   is extremely unlikely.
     */

    mov rax, gs:[0x860]
    cmp rax, 0x1
    jne nmi_pending_transfer_complete

    mov rax, 0x1
    mov [r15 + 0x318], rax

nmi_pending_transfer_complete:

    mov rax, 0x4002
    vmread rax, rax
    jbe nmi_window_transfer_complete

    mov rdx, 0x0000000000400000
    and rax, rdx
    cmp rax, 0x0
    je nmi_window_transfer_complete

    mov rax, 0x1
    mov [r15 + 0x318], rax

 nmi_window_transfer_complete:

    call set_up_target
capture_spec:
    pause
    jmp capture_spec
set_up_target:
    mov rax, [r15 + 0x2E8]
    mov [rsp], rax
    ret
    int 3

    .size promote, .-promote
