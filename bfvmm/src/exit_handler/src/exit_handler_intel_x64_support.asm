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

    vmovdqa [gs:0x0C0], ymm0
    vmovdqa [gs:0x0E0], ymm1
    vmovdqa [gs:0x100], ymm2
    vmovdqa [gs:0x120], ymm3
    vmovdqa [gs:0x140], ymm4
    vmovdqa [gs:0x160], ymm5
    vmovdqa [gs:0x180], ymm6
    vmovdqa [gs:0x1A0], ymm7
    vmovdqa [gs:0x1C0], ymm8
    vmovdqa [gs:0x1E0], ymm9
    vmovdqa [gs:0x200], ymm10
    vmovdqa [gs:0x220], ymm11
    vmovdqa [gs:0x240], ymm12
    vmovdqa [gs:0x260], ymm13
    vmovdqa [gs:0x280], ymm14
    vmovdqa [gs:0x2A0], ymm15

    mov rdi, VMCS_GUEST_RIP
    vmread [gs:0x078], rdi
    mov rdi, VMCS_GUEST_RSP
    vmread [gs:0x080], rdi

    mov rdi, [gs:0x00A0]
    call exit_handler wrt ..plt

    mov rdi, VMCS_GUEST_RSP
    vmwrite rdi, [gs:0x080]
    mov rdi, VMCS_GUEST_RIP
    vmwrite rdi, [gs:0x078]

    vmovdqa ymm15, [gs:0x2A0]
    vmovdqa ymm14, [gs:0x280]
    vmovdqa ymm13, [gs:0x260]
    vmovdqa ymm12, [gs:0x240]
    vmovdqa ymm11, [gs:0x220]
    vmovdqa ymm10, [gs:0x200]
    vmovdqa ymm9,  [gs:0x1E0]
    vmovdqa ymm8,  [gs:0x1C0]
    vmovdqa ymm7,  [gs:0x1A0]
    vmovdqa ymm6,  [gs:0x180]
    vmovdqa ymm5,  [gs:0x160]
    vmovdqa ymm4,  [gs:0x140]
    vmovdqa ymm3,  [gs:0x120]
    vmovdqa ymm2,  [gs:0x100]
    vmovdqa ymm1,  [gs:0x0E0]
    vmovdqa ymm0,  [gs:0x0C0]

    mov r15, [gs:0x070]
    mov r14, [gs:0x068]
    mov r13, [gs:0x060]
    mov r12, [gs:0x058]
    mov r11, [gs:0x050]
    mov r10, [gs:0x048]
    mov r9,  [gs:0x040]
    mov r8,  [gs:0x038]
    mov rdi, [gs:0x030]
    mov rsi, [gs:0x028]
    mov rbp, [gs:0x020]
    mov rdx, [gs:0x018]
    mov rcx, [gs:0x010]
    mov rbx, [gs:0x008]
    mov rax, [gs:0x000]

    sti

    vmresume
