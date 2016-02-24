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
global exit_handler_entry
global promote_vmcs_to_root

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


;; VMCS Promotion
promote_vmcs_to_root:
    mov rax, [g_guest_rip]
    mov rsp, [g_guest_rsp]
    push rax

    mov rdi, [g_guest_rdi]
    mov rsi, [g_guest_rsi]
    mov rbp, [g_guest_rbp]

    mov rdx, [g_guest_rdx]
    mov rcx, [g_guest_rcx]
    mov rbx, [g_guest_rbx]
    mov rax, [g_guest_rax]
    mov r15, [g_guest_r15]
    mov r14, [g_guest_r14]
    mov r13, [g_guest_r13]
    mov r12, [g_guest_r12]
    mov r11, [g_guest_r11]
    mov r10, [g_guest_r10]
    mov r9,  [g_guest_r09]
    mov r8,  [g_guest_r08]
    mov rsp, [g_guest_rsp]

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

    ; Registers
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

    ; RSP, RIP
    mov rdi, VMCS_GUEST_RSP
    vmread [g_guest_rsp], rdi
    mov rdi, VMCS_GUEST_RIP
    vmread [g_guest_rip], rdi

    call exit_handler wrt ..plt

    ; RIP, RSP
    mov rdi, VMCS_GUEST_RIP
    vmwrite rdi, [g_guest_rip]
    mov rdi, VMCS_GUEST_RSP
    vmwrite rdi, [g_guest_rsp]

    ; Registers
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

; VMM Guest Instructions
;
; Certain instructions are better optimized, if they have direct access to the
; guest state. The exit handler can use the information that is stored in the
; resulting guest state as needed, or it can choose to pass on the resulting
; state back to the guest. These functions provide these optimized instructions
;
; Note that some of these instructions only modify the first 32 bits of the
; registers. Since we do not know what ABI will be running as it could be
; System V or MS x64, we cannot assume what state the upper bits of these
; registers should be left in. For this reason, when we execute these
; instructions, we first load the guest state into the register, and then allow
; the instruction to execute as expected, and then save the result, thus
; preserving the upper bits of each register that would be affected by the
; instruction. It's still possible for the exit handler to modify from there
; as needed, but at least the starting point of the instruction is preserving
; the state of the guest

global guest_cpuid:function
global guest_read_msr:function
global guest_write_msr:function

; void guest_cpuid(void)
guest_cpuid:
    push rbx
    push rcx
    push rdx

    mov rax, [g_guest_rax]
    mov rbx, [g_guest_rbx]
    mov rcx, [g_guest_rcx]
    mov rdx, [g_guest_rdx]

    cpuid

    mov [g_guest_rax], rax
    mov [g_guest_rbx], rbx
    mov [g_guest_rcx], rcx
    mov [g_guest_rdx], rdx

    mov rax, 0

    pop rdx
    pop rcx
    pop rbx
    ret

; void guest_read_msr(void)
guest_read_msr:
    push rcx
    push rdx

    mov rax, [g_guest_rax]
    mov rcx, [g_guest_rcx]
    mov rdx, [g_guest_rdx]

    rdmsr

    mov [g_guest_rax], rax
    mov [g_guest_rdx], rdx

    mov rax, 0

    pop rdx
    pop rcx
    ret

; void guest_write_msr(void)
guest_write_msr:
    push rcx
    push rdx

    mov rcx, [g_guest_rcx]
    mov rax, [g_guest_rax]
    mov rdx, [g_guest_rdx]

    wrmsr

    mov rax, 0

    pop rdx
    pop rcx
    ret

