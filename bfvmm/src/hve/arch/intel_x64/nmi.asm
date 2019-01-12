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

%define VMCS_PRIMARY_EXEC_CTL 0x00004002
%define NMI_WINDOW_EXITING    0x00400000

section .text

%macro PUSHALL 0
    sub rsp, 16
    movups [rsp], xmm0
    sub rsp, 16
    movups [rsp], xmm1
    sub rsp, 16
    movups [rsp], xmm2
    sub rsp, 16
    movups [rsp], xmm3
    sub rsp, 16
    movups [rsp], xmm4
    sub rsp, 16
    movups [rsp], xmm5
    sub rsp, 16
    movups [rsp], xmm6
    sub rsp, 16
    movups [rsp], xmm7

    push rax
    push rbx
    push rcx
    push rdx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
%endmacro

%macro POPALL 0
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rdx
    pop rcx
    pop rbx
    pop rax

    movups xmm7, [rsp]
    add rsp, 16
    movups xmm6, [rsp]
    add rsp, 16
    movups xmm5, [rsp]
    add rsp, 16
    movups xmm4, [rsp]
    add rsp, 16
    movups xmm3, [rsp]
    add rsp, 16
    movups xmm2, [rsp]
    add rsp, 16
    movups xmm1, [rsp]
    add rsp, 16
    movups xmm0, [rsp]
    add rsp, 16
%endmacro

global _handle_nmi
_handle_nmi:
    PUSHALL
    mov rsi, VMCS_PRIMARY_EXEC_CTL
    vmread rdi, rsi
    or rdi, NMI_WINDOW_EXITING
    vmwrite rsi, rdi
    POPALL
    iretq
