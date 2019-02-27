;
; Copyright (C) 2019 Assured Information Security, Inc.
;
; Permission is hereby granted, free of charge, to any person obtaining a copy
; of this software and associated documentation files (the "Software"), to deal
; in the Software without restriction, including without limitation the rights
; to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
; copies of the Software, and to permit persons to whom the Software is
; furnished to do so, subject to the following conditions:
;
; The above copyright notice and this permission notice shall be included in all
; copies or substantial portions of the Software.
;
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
; OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
; SOFTWARE.

bits 64
default rel

%define VMCS_GUEST_RSP 0x0000681C
%define VMCS_GUEST_RIP 0x0000681E

extern handle_exit
global exit_handler_entry:function

section .text

; Exit Handler Entry Point
;
; With respect to VT-x, when an exit occurs, the CPU keeps the state of the
; registers from the guest intact, and gives the state of the registers prior
; to vmresume, back to the guest. The only exception to this is RSP and RIP as
; these two registers are specific to the VMM (RIP is exit_handler_entry,
; and RSP is the exit_handler_stack). So the only job that this entry point
; has is to preserve the state of the guest
;
exit_handler_entry:

    mov [gs:0x000], rax
    mov [gs:0x008], rbx
    mov [gs:0x010], rcx
    mov [gs:0x018], rdx
    mov [gs:0x020], rbp
    mov [gs:0x028], rsi
    mov [gs:0x030], rdi
    mov [gs:0x038], r8
    mov [gs:0x040], r9
    mov [gs:0x048], r10
    mov [gs:0x050], r11
    mov [gs:0x058], r12
    mov [gs:0x060], r13
    mov [gs:0x068], r14
    mov [gs:0x070], r15

    movdqa [gs:0x0C0], xmm0
    movdqa [gs:0x0E0], xmm1
    movdqa [gs:0x100], xmm2
    movdqa [gs:0x120], xmm3
    movdqa [gs:0x140], xmm4
    movdqa [gs:0x160], xmm5
    movdqa [gs:0x180], xmm6
    movdqa [gs:0x1A0], xmm7

    mov rdi, VMCS_GUEST_RIP
    vmread [gs:0x078], rdi
    mov rdi, VMCS_GUEST_RSP
    vmread [gs:0x080], rdi

    mov rdi, [gs:0x0098]
    mov rsi, [gs:0x00A0]
    call handle_exit wrt ..plt

; The code should never get this far as the exit handler should resume back
; into the guest using the VMCS's resume function. If we get this far,
; something really bad has happened as we also halt in exit_handler if the
; resume doesn't happen.

    hlt
