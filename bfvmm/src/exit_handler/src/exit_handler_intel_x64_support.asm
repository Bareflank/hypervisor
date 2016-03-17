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

global g_guest_rax:data
global g_guest_rbx:data
global g_guest_rcx:data
global g_guest_rdx:data
global g_guest_rbp:data
global g_guest_rsi:data
global g_guest_rdi:data
global g_guest_r08:data
global g_guest_r09:data
global g_guest_r10:data
global g_guest_r11:data
global g_guest_r12:data
global g_guest_r13:data
global g_guest_r14:data
global g_guest_r15:data
global g_guest_rsp:data
global g_guest_rip:data

extern exit_handler
global exit_handler_entry:function
global promote_vmcs_to_root:function

section .data

g_guest_rax dq 0
g_guest_rbx dq 0
g_guest_rcx dq 0
g_guest_rdx dq 0
g_guest_rbp dq 0
g_guest_rsi dq 0
g_guest_rdi dq 0
g_guest_r08 dq 0
g_guest_r09 dq 0
g_guest_r10 dq 0
g_guest_r11 dq 0
g_guest_r12 dq 0
g_guest_r13 dq 0
g_guest_r14 dq 0
g_guest_r15 dq 0
g_guest_rsp dq 0
g_guest_rip dq 0

section .text

; Promote VMCS
;
; Continues execution using the Guest state. Once this function execute,
; the host VMM will stop executing, and the guest will execute at the
; instruction that it exited on (likely the vmxoff instruction)
;
promote_vmcs_to_root:

    mov rsp, [g_guest_rsp]
    mov rax, [g_guest_rip]
    push rax

    mov r15, [g_guest_r15]
    mov r14, [g_guest_r14]
    mov r13, [g_guest_r13]
    mov r12, [g_guest_r12]
    mov r11, [g_guest_r11]
    mov r10, [g_guest_r10]
    mov r9,  [g_guest_r09]
    mov r8,  [g_guest_r08]
    mov rdi, [g_guest_rdi]
    mov rsi, [g_guest_rsi]
    mov rbp, [g_guest_rbp]
    mov rdx, [g_guest_rdx]
    mov rcx, [g_guest_rcx]
    mov rbx, [g_guest_rbx]
    mov rax, [g_guest_rax]

    sti
    ret

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
; guest. Note that the guest's registers are globally defined, which means that
; the exit handler has the ability to modify these registers if needed, which
; is likely to occur.
;
exit_handler_entry:

    cli

    mov [g_guest_rax], rax
    mov [g_guest_rbx], rbx
    mov [g_guest_rcx], rcx
    mov [g_guest_rdx], rdx
    mov [g_guest_rbp], rbp
    mov [g_guest_rsi], rsi
    mov [g_guest_rdi], rdi
    mov [g_guest_r08], r8
    mov [g_guest_r09], r9
    mov [g_guest_r10], r10
    mov [g_guest_r11], r11
    mov [g_guest_r12], r12
    mov [g_guest_r13], r13
    mov [g_guest_r14], r14
    mov [g_guest_r15], r15

    mov rdi, VMCS_GUEST_RIP
    vmread [g_guest_rip], rdi
    mov rdi, VMCS_GUEST_RSP
    vmread [g_guest_rsp], rdi

    call exit_handler wrt ..plt

    mov rdi, VMCS_GUEST_RSP
    vmwrite rdi, [g_guest_rsp]
    mov rdi, VMCS_GUEST_RIP
    vmwrite rdi, [g_guest_rip]

    mov r15, [g_guest_r15]
    mov r14, [g_guest_r14]
    mov r13, [g_guest_r13]
    mov r12, [g_guest_r12]
    mov r11, [g_guest_r11]
    mov r10, [g_guest_r10]
    mov r9,  [g_guest_r09]
    mov r8,  [g_guest_r08]
    mov rdi, [g_guest_rdi]
    mov rsi, [g_guest_rsi]
    mov rbp, [g_guest_rbp]
    mov rdx, [g_guest_rdx]
    mov rcx, [g_guest_rcx]
    mov rbx, [g_guest_rbx]
    mov rax, [g_guest_rax]

    sti

    vmresume
