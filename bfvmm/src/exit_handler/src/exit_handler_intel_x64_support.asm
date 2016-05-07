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

%define VMCS_GUEST_RSP 0x0000681C
%define VMCS_GUEST_RIP 0x0000681E

extern exit_handler
global exit_handler_entry:function

section .text

; VMM Entry Point
;
; The exit handler is the actual VMM. It's the peice of code that sits above
; the guest OS, and monitors what it's doing, and based on the different types
; of exit conditions, changes the guest's operations to suit it's needs.
;
; With respect to VT-x, when the exit occurs, the CPU keeps the state of the
; registers from the guest intact, and gives the state of the registers prior
; to vmresume, back to the guest. The only exception to this is RSP and RIP as
; these two registers are specific to the VMM (RIP is exit_handler_entry,
; and RSP is the exit_handler_stack). So the only job that this entry point
; has is to preserve the state of the guest, and restore the state of the
; guest.
;
; NOTE: The order of these registers and their indexes depend on the
;       state save structure in the intrinsics code. If you change that
;       code, make sure you update this code to reflect the change.
;
exit_handler_entry:

    cli

    mov [gs:0x00], rax
    mov [gs:0x08], rbx
    mov [gs:0x10], rcx
    mov [gs:0x18], rdx
    mov [gs:0x20], rbp
    mov [gs:0x28], rsi
    mov [gs:0x30], rdi
    mov [gs:0x38], r8
    mov [gs:0x40], r9
    mov [gs:0x48], r10
    mov [gs:0x50], r11
    mov [gs:0x58], r12
    mov [gs:0x60], r13
    mov [gs:0x68], r14
    mov [gs:0x70], r15

    mov rdi, VMCS_GUEST_RIP
    vmread [gs:0x78], rdi
    mov rdi, VMCS_GUEST_RSP
    vmread [gs:0x80], rdi

    mov rdi, [gs:0x0A0]
    call exit_handler wrt ..plt

    mov rdi, VMCS_GUEST_RSP
    vmwrite rdi, [gs:0x80]
    mov rdi, VMCS_GUEST_RIP
    vmwrite rdi, [gs:0x78]

    mov r15, [gs:0x70]
    mov r14, [gs:0x68]
    mov r13, [gs:0x60]
    mov r12, [gs:0x58]
    mov r11, [gs:0x50]
    mov r10, [gs:0x48]
    mov r9,  [gs:0x40]
    mov r8,  [gs:0x38]
    mov rdi, [gs:0x30]
    mov rsi, [gs:0x28]
    mov rbp, [gs:0x20]
    mov rdx, [gs:0x18]
    mov rcx, [gs:0x10]
    mov rbx, [gs:0x08]
    mov rax, [gs:0x00]

    sti

    vmresume
