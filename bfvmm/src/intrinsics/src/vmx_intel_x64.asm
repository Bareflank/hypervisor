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

section .text

global __vmxon:function
__vmxon:
    vmxon [rdi]
    jbe __vmx_failure
    jmp __vmx_success

global __vmxoff:function
__vmxoff:
    vmxoff
    jbe __vmx_failure
    jmp __vmx_success

global __vmclear:function
__vmclear:
    vmclear [rdi]
    jbe __vmx_failure
    jmp __vmx_success

global __vmptrld:function
__vmptrld:
    vmptrld [rdi]
    jbe __vmx_failure
    jmp __vmx_success

global __vmptrst:function
__vmptrst:
    vmptrst [rdi]
    jbe __vmx_failure
    jmp __vmx_success

global __vmread:function
__vmread:
    vmread [rsi], rdi
    jbe __vmx_failure
    jmp __vmx_success

global __vmwrite:function
__vmwrite:
    vmwrite rdi, rsi
    jbe __vmx_failure
    jmp __vmx_success

; The following provides a traditional VM launch. One issue with VM launch is
; that the initial register state of the guest is equal to the register state
; right before the launch. For a traditional vm launch that might be executing
; a guest, we have to first clear the register state to ensure we don't leak
; hypervisor specific stuff to the guest. The problem with this is if the
; instruction fails, we need to be able to get back to the original state, so
; we first store the state on the stack, clear the state, and then reset the
; state on failure. Also note that we allow for two parameters to be passed
; via rdi and rsi.
;
; TODO: XMM registers
; TODO: FPU registers

global __vmlaunch:function
__vmlaunch:

    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp

    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    xor rdx, rdx
    xor rbp, rbp
    xor r8, r8
    xor r9, r9
    xor r10, r10
    xor r11, r11
    xor r12, r12
    xor r13, r13
    xor r14, r14
    xor r15, r15

    vmlaunch

    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx

    jbe __vmx_failure
    jmp __vmx_success

; Since bareflank consists of nothing more than a bunch of shared libraries,
; all of the code is position independent, which makes getting the actual
; address of a label difficult at compile time since everything is going to be
; relocated. In the case of the VMM, RIP is simple, as we can provide a
; custom entry point that we can control. In the case of the guest, RIP needs
; to continue execution of the guest, which is somewhere in the call stack of
; the driver entry point. One easy way to solve this problem, is to grab a
; return address off the stack, since the return addresses on the stack are
; already relocated for us.
;
; So this function sets up the last two fields in the VMCS with the stack and
; RIP that it has right before vmlaunch occurs. Since we popped the return
; address off the stack, the "ret" instruction cannot be used as our stack is
; corrupt. If the vmlaunch is successful, rax will have a 1 in it because
; the launch will "appear" like a "ret", handing control back to the
; original __vmlaunch call. If the launch fails, it will execute the next
; instruction which will cause rax to be false, and hand control over to
; continue execution.
;

global __vmlaunch_demote:function
__vmlaunch_demote:
    call __vmlaunch_trampoline
    ret

__vmlaunch_trampoline:

    pop rsi

    mov rdi, 0x0000681E     ; VMCS_GUEST_RIP
    vmwrite rdi, rsi

    mov rdi, 0x0000681C     ; VMCS_GUEST_RSP
    vmwrite rdi, rsp

    mov rax, 0x1
    vmlaunch
    mov rax, 0x0

    jmp rsi

global __invept:function
__invept:
    invept rdi, [rsi]
    jbe __vmx_failure
    jmp __vmx_success

global __invvpid:function
__invvpid:
    invvpid rdi, [rsi]
    jbe __vmx_failure
    jmp __vmx_success

; Failure Routines

__vmx_failure:
    mov rax, 0x0
    ret

__vmx_success:
    mov rax, 0x1
    ret
