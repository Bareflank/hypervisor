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

; int64_t execute_entry(void *stack, void *func, uint64_t arg1, uint64_t arg2);
;
; r08 -> xsave enabled bits
; r09 -> xsave enabled bits
; r10 -> size of xsave area
; r11 -> func return value
; r12 ->
; r13 -> func pointer
; r14 -> arg1
; r15 -> arg2
;
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

    mov rsp, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx

    mov rcx, 0x00
    xgetbv
    mov r8, rax
    mov r9, rdx

    mov rax, 0x0D
    mov rbx, 0x00
    mov rcx, 0x00
    mov rdx, 0x00
    cpuid
    mov r10, rcx

    sub rsp, r10
    sub rsp, 0x40
    and rsp, 0xFFFFFFFFFFFFFF80

    mov rcx, r10
    mov rax, 0x00
    mov rdi, rsp
    rep
    stosb

    mov rax, r8
    mov rdx, r9
    xsave [rsp]

    push r8
    push r9
    push r10

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

    pop r10
    pop r9
    pop r8

    mov rax, r8
    mov rdx, r9
    xrstor [rsp]

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
