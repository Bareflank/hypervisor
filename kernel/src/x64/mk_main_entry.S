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

    .globl  mk_main_entry
    .type   mk_main_entry, @function
mk_main_entry:

    push rdi

    mov r10, [rdi]
    mov rdx, 0x000000000000FFFF
    and r10, rdx

    mov rax, r10
    mov rdx, 0x1000
    mul rdx
    lea rsi, [rip + g_tls_blocks]
    add rsi, rax

    mov ecx, 0xC0000101
    mov rax, rsi
    mov rdx, rsi
    shr rdx, 32
    wrmsr

    push rsi
    push rdi

    mov rax, r10
    mov rdx, 0xFFFFFFFFFFFF0000
    or  rax, rdx

    mov gs:[0x800], rsi
    mov gs:[0x808], rax

    lea rax, [rip + mk_main_fast_fail_entry]
    mov gs:[0x910], rax
    lea rax, [rip + call_ext_fast_fail_entry]
    mov gs:[0x920], rax
    lea rax, [rip + dispatch_syscall_fast_fail_entry]
    mov gs:[0x930], rax

    mov rax, [rdi + 0x008]
    mov gs:[0x828], rax
    mov rax, [rdi + 0x010]
    mov gs:[0x830], rax

    lea rax, [rip + g_debug_ring]
    mov rdx, [rdi + 0x018]
    mov [rax], rdx

    /**
     * NOTE:
     * - Set up the IDT with the actual ESRs. Before we can do this, we need
     *   to lock NMIs. Any NMIs that come in can only set the pending bit
     *   in the TLS until a run occurs. Once a run occurs, we can handle
     *   the NMI from there (or the promote logic will handle it in the
     *   event that an error occurs).
     * - Once we install the new ESRs, we can transfer the NMI bit from the
     *   root state to the TLS.
     */

    mov rax, 0x1
    mov gs:[0x858], rax

    mov rdi, 0
    lea rsi, [rip + dispatch_esr_entry_0]
    call set_esr

    mov rdi, 1
    lea rsi, [rip + dispatch_esr_entry_1]
    call set_esr

    mov rdi, 2
    lea rsi, [rip + dispatch_esr_entry_2]
    call set_esr

    mov rdi, 3
    lea rsi, [rip + dispatch_esr_entry_3]
    call set_esr

    mov rdi, 4
    lea rsi, [rip + dispatch_esr_entry_4]
    call set_esr

    mov rdi, 5
    lea rsi, [rip + dispatch_esr_entry_5]
    call set_esr

    mov rdi, 6
    lea rsi, [rip + dispatch_esr_entry_6]
    call set_esr

    mov rdi, 7
    lea rsi, [rip + dispatch_esr_entry_7]
    call set_esr

    mov rdi, 8
    lea rsi, [rip + dispatch_esr_entry_8]
    call set_esr

    mov rdi, 10
    lea rsi, [rip + dispatch_esr_entry_10]
    call set_esr

    mov rdi, 11
    lea rsi, [rip + dispatch_esr_entry_11]
    call set_esr

    mov rdi, 12
    lea rsi, [rip + dispatch_esr_entry_12]
    call set_esr

    mov rdi, 13
    lea rsi, [rip + dispatch_esr_entry_13]
    call set_esr

    mov rdi, 14
    lea rsi, [rip + dispatch_esr_entry_14]
    call set_esr

    mov rdi, 16
    lea rsi, [rip + dispatch_esr_entry_16]
    call set_esr

    mov rdi, 17
    lea rsi, [rip + dispatch_esr_entry_17]
    call set_esr

    mov rdi, 18
    lea rsi, [rip + dispatch_esr_entry_18]
    call set_esr

    mov rdi, 19
    lea rsi, [rip + dispatch_esr_entry_19]
    call set_esr

    mov ecx, 0xC0000082
    lea rax, [rip + dispatch_syscall_entry]
    mov rdx, rax
    shr rdx, 32
    wrmsr

    pop rdi

    mov rdx, [rdi + 0x010]
    mov rax, [rdx + 0x318]
    mov gs:[0x860], rax

    xor rax, rax
    mov [rdx + 0x318], rax

    pop rsi

    mov gs:[0x918], rsp
    mov rax, gs:[0x910]
    mov gs:[0x900], rax
    mov rax, gs:[0x918]
    mov gs:[0x908], rax

    call mk_main_trampoline
    jmp return_to_current_fast_fail

    .size mk_main_entry, .-mk_main_entry

    /**************************************************************************/
    /* Fast Fail Routine                                                      */
    /**************************************************************************/

    .globl  mk_main_fast_fail_entry
    .type   mk_main_fast_fail_entry, @function
mk_main_fast_fail_entry:

    pop rdi

    mov rdi, [rdi + 0x010]
    mov rsi, 1
    jmp promote

    .size mk_main_fast_fail_entry, .-mk_main_fast_fail_entry
