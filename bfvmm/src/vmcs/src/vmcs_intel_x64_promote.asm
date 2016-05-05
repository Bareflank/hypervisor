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

global promote_vmcs_to_root:function

section .text

; Promote VMCS
;
; Continues execution using the Guest state. Once this function execute,
; the host VMM will stop executing, and the guest will execute at the
; instruction that it exited on (likely the vmxoff instruction)
;
; NOTE: The order of these registers and their indexes depend on the
;       state save structure in the intrinsics code. If you change that
;       code, make sure you update this code to reflect the change.
;
promote_vmcs_to_root:

    mov rsp, [rdi + 0x80]
    mov rax, [rdi + 0x78]
    push rax

    mov r15, [rdi + 0x70]
    mov r14, [rdi + 0x68]
    mov r13, [rdi + 0x60]
    mov r12, [rdi + 0x58]
    mov r11, [rdi + 0x50]
    mov r10, [rdi + 0x48]
    mov r9,  [rdi + 0x40]
    mov r8,  [rdi + 0x38]
    mov rsi, [rdi + 0x28]
    mov rbp, [rdi + 0x20]
    mov rdx, [rdi + 0x18]
    mov rcx, [rdi + 0x10]
    mov rbx, [rdi + 0x08]
    mov rax, [rdi + 0x00]

    mov rdi, [rdi + 0x30]

    sti
    ret
