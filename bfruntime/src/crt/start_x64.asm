;
; Bareflank Hypervisor
; Copyright (C) 2015 Assured Information Security, Inc.
;
; This library is free software; you can redistribute it and/or
; modify it under the terms of the GNU Lesser General Public
; License as published by the Free Software Foundation; either
; version 2.1 of the License, or (at your option) any later version.
;
; This library is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
; Lesser General Public License for more details.
;
; You should have received a copy of the GNU Lesser General Public
; License along with this library; if not, write to the Free Software
; Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

bits 64
default rel

extern _start_c
global _start:function

section .text

; int64_t _start(uint64_t stack, crt_info_t *crt_info);
_start:

    push rbx
    push rcx
    push rdx
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

    push rbp
    mov rbp, rsp

%ifdef MS64
    mov rsp, rcx    ; stack
    mov r13, rdx    ; crt_info
%else
    mov rsp, rdi    ; stack
    mov r13, rsi    ; crt_info
%endif

    and rsp, 0xFFFFFFFFFFFFFFE0

    sub rsp, 0x20
    movdqa [rsp], xmm0
    sub rsp, 0x20
    movdqa [rsp], xmm1
    sub rsp, 0x20
    movdqa [rsp], xmm2
    sub rsp, 0x20
    movdqa [rsp], xmm3
    sub rsp, 0x20
    movdqa [rsp], xmm4
    sub rsp, 0x20
    movdqa [rsp], xmm5
    sub rsp, 0x20
    movdqa [rsp], xmm6
    sub rsp, 0x20
    movdqa [rsp], xmm7

    mov rax, 0xABCDEF1234567890
    push rax

    mov rdi, r13
    call _start_c wrt ..plt
    mov r11, rax

    pop rax
    mov rbx, 0xABCDEF1234567890
    cmp rax, rbx
    jne stack_overflow

    movdqa [rsp], xmm7
    add rsp, 0x20
    movdqa [rsp], xmm6
    add rsp, 0x20
    movdqa [rsp], xmm5
    add rsp, 0x20
    movdqa [rsp], xmm4
    add rsp, 0x20
    movdqa [rsp], xmm3
    add rsp, 0x20
    movdqa [rsp], xmm2
    add rsp, 0x20
    movdqa [rsp], xmm1
    add rsp, 0x20
    movdqa [rsp], xmm0
    add rsp, 0x20

    mov rax, r11
    leave

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
    pop rdx
    pop rcx
    pop rbx

    ret

stack_overflow:

    mov rax, 0x8000000000000010
    leave

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
    pop rdx
    pop rcx
    pop rbx

    ret
