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

section .text

%ifdef MS64

; ------------------------------------------------------------------------------
; MS64
; ------------------------------------------------------------------------------

global vmcall:function
vmcall:

    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15

    mov rdi, rcx

    mov rax, [rdi + 0x00]
    mov rdx, [rdi + 0x08]
    mov rcx, [rdi + 0x10]
    mov rbx, [rdi + 0x18]
    mov rsi, [rdi + 0x20]
    mov r8,  [rdi + 0x28]
    mov r9,  [rdi + 0x30]
    mov r10, [rdi + 0x38]
    mov r11, [rdi + 0x40]
    mov r12, [rdi + 0x48]
    mov r13, [rdi + 0x50]
    mov r14, [rdi + 0x58]
    mov r15, [rdi + 0x60]

    vmcall

    mov [rdi + 0x60], r15
    mov [rdi + 0x58], r14
    mov [rdi + 0x50], r13
    mov [rdi + 0x48], r12
    mov [rdi + 0x40], r11
    mov [rdi + 0x38], r10
    mov [rdi + 0x30], r9
    mov [rdi + 0x28], r8
    mov [rdi + 0x20], rsi
    mov [rdi + 0x18], rbx
    mov [rdi + 0x10], rcx
    mov [rdi + 0x08], rdx

    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx

    ret

global vmcall_event:function
vmcall_event:

    push rdi
    mov rdi, rcx

    mov rax, [rdi + 0x00]
    mov rdx, [rdi + 0x08]
    mov rcx, [rdi + 0x10]

    vmcall

    mov [rdi + 0x08], rdx

    pop rdi
    ret

%else

; ------------------------------------------------------------------------------
; SYSV
; ------------------------------------------------------------------------------

global vmcall:function
vmcall:

    push rbx
    push r12
    push r13
    push r14
    push r15

    mov rax, [rdi + 0x00]
    mov rdx, [rdi + 0x08]
    mov rcx, [rdi + 0x10]
    mov rbx, [rdi + 0x18]
    mov rsi, [rdi + 0x20]
    mov r8,  [rdi + 0x28]
    mov r9,  [rdi + 0x30]
    mov r10, [rdi + 0x38]
    mov r11, [rdi + 0x40]
    mov r12, [rdi + 0x48]
    mov r13, [rdi + 0x50]
    mov r14, [rdi + 0x58]
    mov r15, [rdi + 0x60]

    vmcall

    mov [rdi + 0x60], r15
    mov [rdi + 0x58], r14
    mov [rdi + 0x50], r13
    mov [rdi + 0x48], r12
    mov [rdi + 0x40], r11
    mov [rdi + 0x38], r10
    mov [rdi + 0x30], r9
    mov [rdi + 0x28], r8
    mov [rdi + 0x20], rsi
    mov [rdi + 0x18], rbx
    mov [rdi + 0x10], rcx
    mov [rdi + 0x08], rdx

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx

    ret

global vmcall_event:function
vmcall_event:

    mov rax, [rdi + 0x00]
    mov rdx, [rdi + 0x08]
    mov rcx, [rdi + 0x10]

    vmcall

    mov [rdi + 0x08], rdx

    ret

%endif
