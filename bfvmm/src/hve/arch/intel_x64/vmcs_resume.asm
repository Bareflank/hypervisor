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

bits 64
default rel

%define IA32_XSS_MSR   0xDA0
%define VMCS_GUEST_RSP 0x0000681C
%define VMCS_GUEST_RIP 0x0000681E

global vmcs_resume:function

section .text

; Resume VMCS
;
; Resumes the execution of an already launched VMCS. Note that this function
; should not return. If it does, an error has occurred.
;
vmcs_resume:

    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp

    mov rsi, [rdi + 0x108]
    mov dr6, rsi
    mov rsi, [rdi + 0x100]
    mov dr3, rsi
    mov rsi, [rdi + 0x0F8]
    mov dr2, rsi
    mov rsi, [rdi + 0x0F0]
    mov dr1, rsi
    mov rsi, [rdi + 0x0E8]
    mov dr0, rsi
    mov rsi, [rdi + 0x0E0]
    mov cr8, rsi
    mov rsi, [rdi + 0x0D8]
    mov cr2, rsi

    ; In the exit handler entry point, we set xcr0 and xss to all enabled
    ; bits, which means that the entire CPU state that is supported by
    ; xsave will be reset with the instructions below. If the OS sets any
    ; of these bits, they will be restored by xrstors, otherwise they will
    ; be initialized. When working with multiple guest VMs, it is possible
    ; that some guest VMs will only use a small portion of the xsave state
    ; while others will use all of it. When a world switch occurs (i.e.,
    ; swapping from one VM to another), we need to make sure that none of
    ; this state leaks between guests. This scheme ensures that. Once we
    ; restore the state, we then set the xcr0 and xss to the value the
    ; guest VM expects. Not that this scheme is repeated in the promote and
    ; launch logic.

    mov rsi, [rdi + 0x0C8]
    xor edx, edx
    mov eax, 0xFFFFFFFF
    xrstors64 [rsi]

    mov eax, [rdi + 0x0B8]
    xor edx, edx
    mov ecx, IA32_XSS_MSR
    wrmsr

    mov eax, [rdi + 0x0A8]
    xor edx, edx
    xor ecx, ecx
    xsetbv

    mov rsi, VMCS_GUEST_RSP
    vmwrite rsi, [rdi + 0x080]
    mov rsi, VMCS_GUEST_RIP
    vmwrite rsi, [rdi + 0x078]

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

    vmresume

; We should never get this far. If we do, it's because the resume failed. If
; happens, we return so that we can throw an exception and tell the user that
; something really bad happened.

    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx

    ret
