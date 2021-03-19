; @copyright
; Copyright (C) 2020 Assured Information Security, Inc.
;
; @copyright
; Permission is hereby granted, free of charge, to any person obtaining a copy
; of this software and associated documentation files (the "Software"), to deal
; in the Software without restriction, including without limitation the rights
; to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
; copies of the Software, and to permit persons to whom the Software is
; furnished to do so, subject to the following conditions:
;
; @copyright
; The above copyright notice and this permission notice shall be included in
; all copies or substantial portions of the Software.
;
; @copyright
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
; OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
; SOFTWARE.

    enable_interrupts PROTO
    disable_interrupts PROTO

    demote_text SEGMENT ALIGN(1000h) 'CODE'
    demote PROC

    ; **************************************************************************
    ; General Purpose Registers
    ; **************************************************************************

    mov [r8 + 000h], rax
    mov [r8 + 008h], rbx
    mov [r8 + 010h], rcx
    mov [r8 + 018h], r8
    mov [r8 + 020h], rbp
    mov [r8 + 028h], rsi
    mov [r8 + 030h], rdi
    mov [r8 + 038h], r8
    mov [r8 + 040h], r9
    mov [r8 + 048h], r10
    mov [r8 + 050h], r11
    mov [r8 + 058h], r12
    mov [r8 + 060h], r13
    mov [r8 + 068h], r14
    mov [r8 + 070h], r15

    lea rax, [demotion_success]
    mov [r8 + 078h], rax
    mov [r8 + 080h], rsp

    ; **************************************************************************
    ; Setup
    ; **************************************************************************

    mov r13, rcx       ; args
    mov r14, rdx       ; mk_state
    mov r15, r8        ; root_vp_state

    ; **************************************************************************
    ; Flags
    ; **************************************************************************

    pushfq
    pop [r15 + 088h]
    push [r14 + 088h]
    popf

    ; **************************************************************************
    ; IDT
    ; **************************************************************************

    call disable_interrupts

    sidt fword ptr[r15 + 0B0h]
    lidt fword ptr[r14 + 0B0h]

    ; **************************************************************************
    ; MSRs
    ; **************************************************************************

    mov ecx, 0C0000080h      ; EFER
    rdmsr
    mov [r15 + 240h], eax
    mov [r15 + 244h], edx
    mov eax, [r14 + 240h]
    mov edx, [r14 + 244h]
    wrmsr

    mov ecx, 0C0000081h      ; STAR
    rdmsr
    mov [r15 + 248h], eax
    mov [r15 + 24Ch], edx
    mov eax, [r14 + 248h]
    mov edx, [r14 + 24Ch]
    wrmsr

    mov ecx, 0C0000082h      ; LSTAR
    rdmsr
    mov [r15 + 250h], eax
    mov [r15 + 254h], edx
    mov eax, [r14 + 250h]
    mov edx, [r14 + 254h]
    wrmsr

    mov ecx, 0C0000083h      ; CSTAR
    rdmsr
    mov [r15 + 258h], eax
    mov [r15 + 25Ch], edx
    mov eax, [r14 + 258h]
    mov edx, [r14 + 25Ch]
    wrmsr

    mov ecx, 0C0000084h      ; FMASK
    rdmsr
    mov [r15 + 260h], eax
    mov [r15 + 264h], edx
    mov eax, [r14 + 260h]
    mov edx, [r14 + 264h]
    wrmsr

    mov ecx, 0C0000100h      ; FS Base
    rdmsr
    mov [r15 + 268h], eax
    mov [r15 + 26Ch], edx
    mov eax, [r14 + 268h]
    mov edx, [r14 + 26Ch]
    wrmsr

    mov ecx, 0C0000101h      ; GS Base
    rdmsr
    mov [r15 + 270h], eax
    mov [r15 + 274h], edx
    mov eax, [r14 + 270h]
    mov edx, [r14 + 274h]
    wrmsr

    mov ecx, 0C0000102h      ; Kernel GS Base
    rdmsr
    mov [r15 + 278h], eax
    mov [r15 + 27Ch], edx
    mov eax, [r14 + 278h]
    mov edx, [r14 + 27Ch]
    wrmsr

    mov ecx, 00000174h      ; SYSENTER_CS
    rdmsr
    mov [r15 + 280h], eax
    mov [r15 + 284h], edx
    mov eax, [r14 + 280h]
    mov edx, [r14 + 284h]
    wrmsr

    mov ecx, 00000175h      ; SYSENTER_ESP
    rdmsr
    mov [r15 + 288h], eax
    mov [r15 + 28Ch], edx
    mov eax, [r14 + 288h]
    mov edx, [r14 + 28Ch]
    wrmsr

    mov ecx, 00000176h      ; SYSENTER_EIP
    rdmsr
    mov [r15 + 290h], eax
    mov [r15 + 294h], edx
    mov eax, [r14 + 290h]
    mov edx, [r14 + 294h]
    wrmsr

    mov ecx, 00000277h      ; PAT
    rdmsr
    mov [r15 + 298h], eax
    mov [r15 + 29Ch], edx
    mov eax, [r14 + 298h]
    mov edx, [r14 + 29Ch]
    wrmsr

    mov ecx, 000001D9h      ; DEBUGCTL
    rdmsr
    mov [r15 + 2A0h], eax
    mov [r15 + 2A4h], edx
    mov eax, [r14 + 2A0h]
    mov edx, [r14 + 2A4h]
    wrmsr

    ; **************************************************************************
    ; GDT
    ; **************************************************************************

    sgdt fword ptr[r15 + 0A0h]
    lgdt fword ptr[r14 + 0A0h]

    mov dx, es
    mov [r15 + 0C0h], dx
    mov dx, [r14 + 0C0h]
    mov es, dx

    mov dx, cs
    mov [r15 + 0D0h], dx
    mov ax, [r14 + 0D0h]
    push rax

    mov dx, ss
    mov [r15 + 0E0h], dx
    mov dx, [r14 + 0E0h]
    mov ss, dx

    mov dx, ds
    mov [r15 + 0F0h], dx
    mov dx, [r14 + 0F0h]
    mov ds, dx

    mov dx, fs
    mov [r15 + 100h], dx
    mov dx, [r14 + 100h]
    mov fs, dx

    mov dx, gs
    mov [r15 + 110h], dx
    mov dx, [r14 + 110h]
    mov gs, dx

    mov ecx, 000001D9h
    xor rax, rax
    xor rdx, rdx
    mov ax, [r14 + 110h]
    wrmsr

    sldt dx
    mov [r15 + 120h], dx
    mov dx, [r14 + 120h]
    lldt dx

    str dx
    mov [r15 + 130h], dx
    mov dx, [r14 + 130h]
    ltr dx

    lea rax, [gdt_and_cs_loaded]
    push rax

    retfq

gdt_and_cs_loaded:

    ; **************************************************************************
    ; Control Registers
    ; **************************************************************************

    mov rax, cr0
    mov [r15 + 140h], rax
    mov rax, [r14 + 140h]
    mov cr0, rax

    mov rax, cr2
    mov [r15 + 150h], rax
    mov rax, [r14 + 150h]
    mov cr2, rax

    mov rax, cr4
    mov [r15 + 160h], rax
    mov rax, [r14 + 160h]
    mov cr4, rax

    mov rax, cr3
    mov [r15 + 158h], rax
    mov rax, [r14 + 158h]
    mov cr3, rax

    mov rsp, [r14 + 080h]

    ; **************************************************************************
    ; Debug Registers
    ; **************************************************************************

    mov rax, dr6
    mov [r15 + 1F0h], rax
    mov rax, [r14 + 1F0h]
    mov dr6, rax

    mov rax, dr7
    mov [r15 + 1F8h], rax
    mov rax, [r14 + 1F8h]
    mov dr7, rax

    ; **************************************************************************
    ; Call Microkernel
    ; **************************************************************************

    mov rdi, r13
    push [r14 + 078h]
    ret
    int 3

demotion_success:


    ; NOTE:
    ; - If demotion is successful, before we return back to the loader, we
    ;   ensure that at least one exit occurs. This is done to properly handle
    ;   errors with the first VMExit. Specifically, if the first VMExit
    ;   generates a failure, it needs to return to loader. The state in
    ;   the root VP, which is what it will use to return is still the same
    ;   at this point, so a return is safe.

    push rax
    push rbx
    push rcx
    push rdx

    mov rax, 0
    cpuid

    pop rdx
    pop rcx
    pop rbx
    pop rax

    call enable_interrupts
    ret
    int 3

    demote ENDP
    demote_text ENDS
    end
