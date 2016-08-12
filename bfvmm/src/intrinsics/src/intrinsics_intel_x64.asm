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

global __vmxon:function
global __vmxoff:function
global __vmcall:function
global __vmclear:function
global __vmptrld:function
global __vmptrst:function
global __vmwrite:function
global __vmread:function
global __vmlaunch:function

section .text

; bool __vmxon(void *vmxon_region)
__vmxon:
    vmxon [rdi]
    jbe __vmx_failure
    jmp __vmx_success

; bool __vmxoff(void)
__vmxoff:
    vmxoff
    jbe __vmx_failure
    jmp __vmx_success

; bool __vmcall(uint64_t value)
__vmcall:
    mov rax, rdi
    vmcall
    jbe __vmx_failure
    jmp __vmx_success

; bool __vmclear(void *vmcs_region)
__vmclear:
    vmclear [rdi]
    jbe __vmx_failure
    jmp __vmx_success

; bool __vmptrld(void *vmcs_region)
__vmptrld:
    vmptrld [rdi]
    jbe __vmx_failure
    jmp __vmx_success

; bool __vmptrst(void *vmcs_region)
__vmptrst:
    vmptrst [rdi]
    jbe __vmx_failure
    jmp __vmx_success

; bool __vmwrite(uint64_t field, uint64_t val)
__vmwrite:
    vmwrite rdi, rsi
    jbe __vmx_failure
    jmp __vmx_success

; bool __vmread(uint64_t field, uint64_t *val)
__vmread:
    vmread [rsi], rdi
    jbe __vmx_failure
    jmp __vmx_success

; vmx instruction failed
__vmx_failure:
    mov rax, 0x0
    ret

; vmx instruction succeded
__vmx_success:
    mov rax, 0x1
    ret

; bool __vmlaunch(void)
;
; Since bareflank consists of nothing more than a bunch of shared libraries,
; all of the code is position independent, which makes getting the actual
; address of a labal difficult at compile time since everything is going to be
; relocated. In the case of the VMM, RIP is simple, as we can provide a
; custom entry point that we can control. In the case of the guest, RIP needs
; to continue execution of the guest, which is somewhere in the call stack of
; the driver entry point. One easy way to solve this problem, is to grab a
; return address off the stack, since the return addresses on the stack are
; already relocated for us.
;
; So this function sets up the last two fields in the VMCS with the stack and
; RIP that it has right before vmlaunch occurs. Since we poped the return
; address off the stack, the "ret" instruction cannot be used as our stack is
; corrupt. If the vmlaunch is successful, rax will have a 1 in it because
; the launch will "appear" like a "ret", handing control back to the
; original __vmlaunch call. If the launch fails, it will execute the next
; instruction which will cause rax to be false, and hand control over to
; continue execution.
;

__vmlaunch:
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
