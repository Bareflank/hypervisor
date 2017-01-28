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

; Exit Handler Entry Point
;
; With respect to VT-x, when an exit occurs, the CPU keeps the state of the
; registers from the guest intact, and gives the state of the registers prior
; to vmresume, back to the guest. The only exception to this is RSP and RIP as
; these two registers are specific to the VMM (RIP is exit_handler_entry,
; and RSP is the exit_handler_stack). So the only job that this entry point
; has is to preserve the state of the guest
;
exit_handler_entry:

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

%ifdef AVX_SUPPORTED
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
%else
    movdqa [gs:0x0C0], xmm0
    movdqa [gs:0x0E0], xmm1
    movdqa [gs:0x100], xmm2
    movdqa [gs:0x120], xmm3
    movdqa [gs:0x140], xmm4
    movdqa [gs:0x160], xmm5
    movdqa [gs:0x180], xmm6
    movdqa [gs:0x1A0], xmm7
%endif

    mov rdi, VMCS_GUEST_RIP
    vmread [gs:0x078], rdi
    mov rdi, VMCS_GUEST_RSP
    vmread [gs:0x080], rdi

    mov rdi, [gs:0x00A0]
    call exit_handler wrt ..plt

; The code should never get this far as the exit handler should resume back
; into the guest using the VMCS's resume function. If we get this far,
; something really bad has happened as we also halt in exit_handler if the
; resume doesn't happen.

    hlt
