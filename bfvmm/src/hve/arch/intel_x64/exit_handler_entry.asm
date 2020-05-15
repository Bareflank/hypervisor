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

extern handle_exit
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

    mov rsi, VMCS_GUEST_RIP
    vmread [gs:0x078], rsi
    mov rsi, VMCS_GUEST_RSP
    vmread [gs:0x080], rsi

    ; To handle the XSAVE data, we do not know what the guest is currently
    ; using. One approach would be to save all state and then restore all
    ; of that state. The problem with that approach is if the guest is only
    ; using a small amount of state, this would be wasteful. To prevent
    ; that we use the second approach. In this approach you save what the
    ; guest is using (i.e., save based on the guest's values for xcr0 and
    ; xss), and then restore all state. Any bits that are not saved here
    ; will be initialized to their defaults on restore during a resume.
    ; This ensures that we reduce how much we save (if possible) while still
    ; ensuring the state on resume does not include data from other guest VMs

    xor ecx, ecx
    xgetbv
    mov [gs:0x0A8], eax

    mov rcx, IA32_XSS_MSR
    rdmsr
    mov [gs:0x0B8], eax

    mov rsi, [gs:0x0C8]
    xor edx, edx
    mov eax, 0xFFFFFFFF
    xsaves64 [rsi]

    ; Now that we have saved the guest state based on what the guest was
    ; using, we need to set the xcr0 and xss to all bits (based on what the
    ; cpuid instruction reports). Once that is done, we will restore the
    ; state using a black save area. This ensures that the hypervisor always
    ; have initialized state when it executes. In addition, on resume, this
    ; will ensure that the restore of the state uses all bits as well. Any
    ; state that was not saved by the guest above will be initialized on
    ; resume. Note that since the host state that we restore above never
    ; gets saved (i.e., we never run xsave on it, we only use it for xrstor
    ; to initialize state), we need to flip the bit in the header that tells
    ; xrstor that it is compressed. This ensures we can use the xrstors
    ; instruction which is needed to include xss.

    mov eax, [gs:0x0B0]
    xor edx, edx
    xor ecx, ecx
    xsetbv

    mov eax, [gs:0x0C0]
    xor edx, edx
    mov ecx, IA32_XSS_MSR
    wrmsr

    mov rsi, [gs:0x0D0]
    mov al, 0x80
    mov [rsi + 0x20f], al
    xor edx, edx
    mov eax, 0xFFFFFFFF
    xrstors64 [rsi]

    ; Finally, we need to initialize the remaining control and debug
    ; registers that are not handled by the VMCS. This ensures that the
    ; hypervisor has a clean control and debug register state as it
    ; executes.

    mov rsi, cr2
    mov [gs:0x0D8], rsi
    mov rsi, cr8
    mov [gs:0x0E0], rsi
    mov rsi, dr0
    mov [gs:0x0E8], rsi
    mov rsi, dr1
    mov [gs:0x0F0], rsi
    mov rsi, dr2
    mov [gs:0x0F8], rsi
    mov rsi, dr3
    mov [gs:0x100], rsi
    mov rsi, dr6
    mov [gs:0x108], rsi

    mov rsi, 0x0
    mov cr2, rsi
    mov rsi, 0xF
    mov cr8, rsi
    mov rsi, 0x0
    mov dr0, rsi
    mov rsi, 0x0
    mov dr1, rsi
    mov rsi, 0x0
    mov dr2, rsi
    mov rsi, 0x0
    mov dr3, rsi
    mov rsi, 0x0
    mov dr6, rsi

    mov rdi, [gs:0x0098]
    mov rsi, [gs:0x00A0]
    call handle_exit wrt ..plt

; The code should never get this far as the exit handler should resume back
; into the guest using the VMCS's resume function. If we get this far,
; something really bad has happened as we also halt in exit_handler if the
; resume doesn't happen.

    hlt
