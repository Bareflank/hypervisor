;
; Copyright (C) 2019 Assured Information Security, Inc.
;
; Permission is hereby granted, free of charge, to any person obtaining a copy
; of this software and associated documentation files (the "Software"), to deal
; in the Software without restriction, including without limitation the rights
; to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
; copies of the Software, and to permit persons to whom the Software is
; furnished to do so, subject to the following conditions:
;
; The above copyright notice and this permission notice shall be included in all
; copies or substantial portions of the Software.
;
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
; OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
; SOFTWARE.

section .text

global _vmxon
_vmxon:
    vmxon [rdi]
    jbe _vmx_failure
    jmp _vmx_success

global _vmxoff
_vmxoff:
    vmxoff
    jbe _vmx_failure
    jmp _vmx_success

global _vmclear
_vmclear:
    vmclear [rdi]
    jbe _vmx_failure
    jmp _vmx_success

global _vmptrld
_vmptrld:
    vmptrld [rdi]
    jbe _vmx_failure
    jmp _vmx_success

global _vmptrst
_vmptrst:
    vmptrst [rdi]
    jbe _vmx_failure
    jmp _vmx_success

global _vmread
_vmread:
    vmread [rsi], rdi
    jbe _vmx_failure
    jmp _vmx_success

global _vmwrite
_vmwrite:
    vmwrite rdi, rsi
    jbe _vmx_failure
    jmp _vmx_success

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
; original _vmlaunch call. If the launch fails, it will execute the next
; instruction which will cause rax to be false, and hand control over to
; continue execution.
;

global _vmlaunch_demote
_vmlaunch_demote:
    call _vmlaunch_trampoline
    ret

_vmlaunch_trampoline:

    pop rsi

    mov rdi, 0x0000681E     ; VMCS_GUEST_RIP
    vmwrite rdi, rsi

    mov rdi, 0x0000681C     ; VMCS_GUEST_RSP
    vmwrite rdi, rsp

    mov rax, 0x1
    vmlaunch
    mov rax, 0x0

    jmp rsi

global _invept
_invept:
    invept rdi, [rsi]
    jbe _vmx_failure
    jmp _vmx_success

global _invvpid
_invvpid:
    invvpid rdi, [rsi]
    jbe _vmx_failure
    jmp _vmx_success

; Failure Routines

_vmx_failure:
    mov rax, 0x0
    ret

_vmx_success:
    mov rax, 0x1
    ret

global _vmcall
_vmcall:

    push rbx

%ifdef MS64
    mov rax, rcx
    mov rbx, rdx
    mov rcx, r8
    mov rdx, r9
%else
    mov r10, rdx
    mov r11, rcx

    mov rax, rdi
    mov rbx, rsi
    mov rcx, r10
    mov rdx, r11
%endif

    vmcall

    pop rbx
    ret

global _vmcall1
_vmcall1:

    push rbx

%ifdef MS64
    mov r8,  rcx
%else
    mov r8,  rdi
%endif

    mov rax, [r8]
    mov rbx, 0
    mov rcx, 0
    mov rdx, 0

    vmcall

    mov [r8], rax

    pop rbx
    ret

global _vmcall2
_vmcall2:

    push rbx

%ifdef MS64
    mov r8,  rcx
    mov r9,  rdx
%else
    mov r8,  rdi
    mov r9,  rsi
%endif

    mov rax, [r8]
    mov rbx, [r9]
    mov rcx, 0
    mov rdx, 0

    vmcall

    mov [r8], rax
    mov [r9], rbx

    pop rbx
    ret

global _vmcall3
_vmcall3:

    push rbx

%ifdef MS64
    mov r10, r8
    mov r8,  rcx
    mov r9,  rdx
%else
    mov r8,  rdi
    mov r9,  rsi
    mov r10, rdx
%endif

    mov rax, [r8]
    mov rbx, [r9]
    mov rcx, [r10]
    mov rdx, 0

    vmcall

    mov [r8], rax
    mov [r9], rbx
    mov [r10], rcx

    pop rbx
    ret

global _vmcall4
_vmcall4:

    push rbx

%ifdef MS64
    mov r10, r8
    mov r11, r9
    mov r8,  rcx
    mov r9,  rdx
%else
    mov r8,  rdi
    mov r9,  rsi
    mov r10, rdx
    mov r11, rcx
%endif

    mov rax, [r8]
    mov rbx, [r9]
    mov rcx, [r10]
    mov rdx, [r11]

    vmcall

    mov [r8], rax
    mov [r9], rbx
    mov [r10], rcx
    mov [r11], rdx

    pop rbx
    ret
