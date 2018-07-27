;
; Bareflank Hypervisor
;
; Copyright (C) 2018 Assured Information Security, Inc.
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
