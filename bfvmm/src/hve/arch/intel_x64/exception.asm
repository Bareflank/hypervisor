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

extern default_esr

section .text

%macro PUSHALL 0
    sub rsp, 16
    movdqa [rsp], xmm0
    sub rsp, 16
    movdqa [rsp], xmm1
    sub rsp, 16
    movdqa [rsp], xmm2
    sub rsp, 16
    movdqa [rsp], xmm3
    sub rsp, 16
    movdqa [rsp], xmm4
    sub rsp, 16
    movdqa [rsp], xmm5
    sub rsp, 16
    movdqa [rsp], xmm6
    sub rsp, 16
    movdqa [rsp], xmm7
    sub rsp, 16
    movdqa [rsp], xmm8
    sub rsp, 16
    movdqa [rsp], xmm9
    sub rsp, 16
    movdqa [rsp], xmm10
    sub rsp, 16
    movdqa [rsp], xmm11
    sub rsp, 16
    movdqa [rsp], xmm12
    sub rsp, 16
    movdqa [rsp], xmm13
    sub rsp, 16
    movdqa [rsp], xmm14
    sub rsp, 16
    movdqa [rsp], xmm15

    sub rsp, 8
    stmxcsr [rsp]

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

    ldmxcsr [rsp]
    add rsp, 8

    movdqa xmm15, [rsp]
    add rsp, 16
    movdqa xmm14, [rsp]
    add rsp, 16
    movdqa xmm13, [rsp]
    add rsp, 16
    movdqa xmm12, [rsp]
    add rsp, 16
    movdqa xmm11, [rsp]
    add rsp, 16
    movdqa xmm10, [rsp]
    add rsp, 16
    movdqa xmm9, [rsp]
    add rsp, 16
    movdqa xmm8, [rsp]
    add rsp, 16
    movdqa xmm7, [rsp]
    add rsp, 16
    movdqa xmm6, [rsp]
    add rsp, 16
    movdqa xmm5, [rsp]
    add rsp, 16
    movdqa xmm4, [rsp]
    add rsp, 16
    movdqa xmm3, [rsp]
    add rsp, 16
    movdqa xmm2, [rsp]
    add rsp, 16
    movdqa xmm1, [rsp]
    add rsp, 16
    movdqa xmm0, [rsp]
    add rsp, 16
%endmacro

; The VMM uses the IST mechanism for interrupt handling. One implication
; of this is that the processor unconditionally pushes 5, 8-byte values
; onto the 16-byte aligned stack provided in the IST entry as in the following
; pseudo-code:
;
;    (load rsp with value from IST entry)
;    push ss
;    push old rsp
;    push rflags
;    push cs
;    push rip
;
; If the exception has an error-code, the CPU pushes that too. So if an
; error code is present, the stack is 16-byte aligned, otherwise it is
; 8-byte aligned. In order to use the more-performant movdqa (aligned moves)
; on the XMM registers, we push an extra 8 bytes onto the stack in the
; non-error-code case.

%macro ESR_NOERRCODE 1
    global _esr%1
    _esr%1:
        push rax
        PUSHALL
        mov rdi, %1
        mov rsi, 0
        mov rdx, 0
        mov rcx, rsp
        mov r8,  [gs:0x098]
        call default_esr wrt ..plt
        POPALL
        add rsp, 8
        iretq
%endmacro

%macro ESR_ERRCODE 1
    global _esr%1
    _esr%1:
        PUSHALL
        mov rdi, %1
        mov rsi, [rsp + 384]
        mov rdx, 1
        mov rcx, rsp
        mov r8,  [gs:0x098]
        call default_esr wrt ..plt
        POPALL
        add rsp, 8
        iretq
%endmacro

ESR_NOERRCODE 0
ESR_NOERRCODE 1
ESR_NOERRCODE 2
ESR_NOERRCODE 3
ESR_NOERRCODE 4
ESR_NOERRCODE 5
ESR_NOERRCODE 6
ESR_NOERRCODE 7
ESR_ERRCODE   8
ESR_NOERRCODE 9
ESR_ERRCODE   10
ESR_ERRCODE   11
ESR_ERRCODE   12
ESR_ERRCODE   13
ESR_ERRCODE   14
ESR_NOERRCODE 15
ESR_NOERRCODE 16
ESR_ERRCODE   17
ESR_NOERRCODE 18
ESR_NOERRCODE 19
ESR_NOERRCODE 20
ESR_NOERRCODE 21
ESR_NOERRCODE 22
ESR_NOERRCODE 23
ESR_NOERRCODE 24
ESR_NOERRCODE 25
ESR_NOERRCODE 26
ESR_NOERRCODE 27
ESR_NOERRCODE 28
ESR_NOERRCODE 29
ESR_NOERRCODE 30
ESR_NOERRCODE 31
