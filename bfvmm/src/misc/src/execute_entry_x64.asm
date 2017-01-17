;
; Bareflank Hypervisor
;
; Copyright (C) 2015 Assured Information Security, Inc.
; Author: Rian Quinn        <quinnr@ainfosec.com>
; Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

global execute_entry:function

section .text

; int64_t execute_entry(uint64_t stack, void *func, uint64_t arg1, uint64_t arg2);
execute_entry:

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
    mov rsp, rcx
    mov r13, rdx
    mov r14, r8
    mov r15, r9
%else
    mov rsp, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
%endif

    and rsp, 0xFFFFFFFFFFFFFFE0

%ifdef AVX_SUPPORTED
    sub rsp, 0x20
    vmovdqa [rsp], ymm0
    sub rsp, 0x20
    vmovdqa [rsp], ymm1
    sub rsp, 0x20
    vmovdqa [rsp], ymm2
    sub rsp, 0x20
    vmovdqa [rsp], ymm3
    sub rsp, 0x20
    vmovdqa [rsp], ymm4
    sub rsp, 0x20
    vmovdqa [rsp], ymm5
    sub rsp, 0x20
    vmovdqa [rsp], ymm6
    sub rsp, 0x20
    vmovdqa [rsp], ymm7
    sub rsp, 0x20
    vmovdqa [rsp], ymm8
    sub rsp, 0x20
    vmovdqa [rsp], ymm9
    sub rsp, 0x20
    vmovdqa [rsp], ymm10
    sub rsp, 0x20
    vmovdqa [rsp], ymm11
    sub rsp, 0x20
    vmovdqa [rsp], ymm12
    sub rsp, 0x20
    vmovdqa [rsp], ymm13
    sub rsp, 0x20
    vmovdqa [rsp], ymm14
    sub rsp, 0x20
    vmovdqa [rsp], ymm15
%else
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
%endif

    mov rax, 0xABCDEF1234567890
    push rax

    mov rdi, r14
    mov rsi, r15
    call r13
    mov r11, rax

    pop rax
    mov rbx, 0xABCDEF1234567890
    cmp rax, rbx
    jne stack_overflow

%ifdef AVX_SUPPORTED
    vmovdqa [rsp], ymm15
    add rsp, 0x20
    vmovdqa [rsp], ymm14
    add rsp, 0x20
    vmovdqa [rsp], ymm13
    add rsp, 0x20
    vmovdqa [rsp], ymm12
    add rsp, 0x20
    vmovdqa [rsp], ymm11
    add rsp, 0x20
    vmovdqa [rsp], ymm10
    add rsp, 0x20
    vmovdqa [rsp], ymm9
    add rsp, 0x20
    vmovdqa [rsp], ymm8
    add rsp, 0x20
    vmovdqa [rsp], ymm7
    add rsp, 0x20
    vmovdqa [rsp], ymm6
    add rsp, 0x20
    vmovdqa [rsp], ymm5
    add rsp, 0x20
    vmovdqa [rsp], ymm4
    add rsp, 0x20
    vmovdqa [rsp], ymm3
    add rsp, 0x20
    vmovdqa [rsp], ymm2
    add rsp, 0x20
    vmovdqa [rsp], ymm1
    add rsp, 0x20
    vmovdqa [rsp], ymm0
    add rsp, 0x20
%else
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
%endif

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
