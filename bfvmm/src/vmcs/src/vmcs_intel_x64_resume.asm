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

global vmcs_resume:function

section .text

; Resume VMCS
;
; Resumes the execution of an already launched VMCS. Note that this function
; does not resume, and unlike the entry point, does not use "gs" as we might
; resuming a VM from a different VMCS, and thus, gs is not valid
;
vmcs_resume:

    mov rsi, VMCS_GUEST_RSP
    vmwrite rsi, [rdi + 0x080]
    mov rsi, VMCS_GUEST_RIP
    vmwrite rsi, [rdi + 0x078]

    vmovdqa ymm15, [rdi + 0x2A0]
    vmovdqa ymm14, [rdi + 0x280]
    vmovdqa ymm13, [rdi + 0x260]
    vmovdqa ymm12, [rdi + 0x240]
    vmovdqa ymm11, [rdi + 0x220]
    vmovdqa ymm10, [rdi + 0x200]
    vmovdqa ymm9,  [rdi + 0x1E0]
    vmovdqa ymm8,  [rdi + 0x1C0]
    vmovdqa ymm7,  [rdi + 0x1A0]
    vmovdqa ymm6,  [rdi + 0x180]
    vmovdqa ymm5,  [rdi + 0x160]
    vmovdqa ymm4,  [rdi + 0x140]
    vmovdqa ymm3,  [rdi + 0x120]
    vmovdqa ymm2,  [rdi + 0x100]
    vmovdqa ymm1,  [rdi + 0x0E0]
    vmovdqa ymm0,  [rdi + 0x0C0]

    mov r15, [rdi + 0x070]
    mov r14, [rdi + 0x068]
    mov r13, [rdi + 0x060]
    mov r12, [rdi + 0x058]
    mov r11, [rdi + 0x050]
    mov r10, [rdi + 0x048]
    mov r9,  [rdi + 0x040]
    mov r8,  [rdi + 0x038]
    mov rsi, [rdi + 0x028]
    mov rbp, [rdi + 0x020]
    mov rdx, [rdi + 0x018]
    mov rcx, [rdi + 0x010]
    mov rbx, [rdi + 0x008]
    mov rax, [rdi + 0x000]

    mov rdi, [rdi + 0x030]

    sti
    vmresume

; We should never get this far. If we do, it's because the resume failed. If
; happens, we return so that we can throw an exception and tell the user that
; something really bad happened.

    cli
    ret
