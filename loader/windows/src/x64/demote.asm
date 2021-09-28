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

    ; @brief defines the offset of state_save_t.rax
    SS_OFFSET_RAX EQU 000h
    ; @brief defines the offset of state_save_t.rbx
    SS_OFFSET_RBX EQU 008h
    ; @brief defines the offset of state_save_t.rcx
    SS_OFFSET_RCX EQU 010h
    ; @brief defines the offset of state_save_t.rdx
    SS_OFFSET_RDX EQU 018h
    ; @brief defines the offset of state_save_t.rbp
    SS_OFFSET_RBP EQU 020h
    ; @brief defines the offset of state_save_t.rsi
    SS_OFFSET_RSI EQU 028h
    ; @brief defines the offset of state_save_t.rdi
    SS_OFFSET_RDI EQU 030h
    ; @brief defines the offset of state_save_t.r8
    SS_OFFSET_R8 EQU 038h
    ; @brief defines the offset of state_save_t.r9
    SS_OFFSET_R9 EQU 040h
    ; @brief defines the offset of state_save_t.r10
    SS_OFFSET_R10 EQU 048h
    ; @brief defines the offset of state_save_t.r11
    SS_OFFSET_R11 EQU 050h
    ; @brief defines the offset of state_save_t.r12
    SS_OFFSET_R12 EQU 058h
    ; @brief defines the offset of state_save_t.r13
    SS_OFFSET_R13 EQU 060h
    ; @brief defines the offset of state_save_t.r14
    SS_OFFSET_R14 EQU 068h
    ; @brief defines the offset of state_save_t.r15
    SS_OFFSET_R15 EQU 070h
    ; @brief defines the offset of state_save_t.rip
    SS_OFFSET_RIP EQU 078h
    ; @brief defines the offset of state_save_t.rsp
    SS_OFFSET_RSP EQU 080h
    ; @brief defines the offset of state_save_t.rflags
    SS_OFFSET_RFLAGS EQU 088h
    ; @brief defines the offset of state_save_t.gdtr
    SS_OFFSET_GDTR EQU 0A0h
    ; @brief defines the offset of state_save_t.idtr
    SS_OFFSET_IDTR EQU 0B0h
    ; @brief defines the offset of state_save_t.es_selector
    SS_OFFSET_ES_SELECTOR EQU 0C0h
    ; @brief defines the offset of state_save_t.cs_selector
    SS_OFFSET_CS_SELECTOR EQU 0D0h
    ; @brief defines the offset of state_save_t.ss_selector
    SS_OFFSET_SS_SELECTOR EQU 0E0h
    ; @brief defines the offset of state_save_t.ds_selector
    SS_OFFSET_DS_SELECTOR EQU 0F0h
    ; @brief defines the offset of state_save_t.fs_selector
    SS_OFFSET_FS_SELECTOR EQU 100h
    ; @brief defines the offset of state_save_t.gs_selector
    SS_OFFSET_GS_SELECTOR EQU 110h
    ; @brief defines the offset of state_save_t.ldtr_selector
    SS_OFFSET_LDTR_SELECTOR EQU 120h
    ; @brief defines the offset of state_save_t.tr_selector
    SS_OFFSET_TR_SELECTOR EQU 130h
    ; @brief defines the offset of state_save_t.cr0
    SS_OFFSET_CR0 EQU 140h
    ; @brief defines the offset of state_save_t.cr2
    SS_OFFSET_CR2 EQU 150h
    ; @brief defines the offset of state_save_t.cr3
    SS_OFFSET_CR3 EQU 158h
    ; @brief defines the offset of state_save_t.cr4
    SS_OFFSET_CR4 EQU 160h
    ; @brief defines the offset of state_save_t.cr8
    SS_OFFSET_CR8 EQU 168h
    ; @brief defines the offset of state_save_t.xcr0
    SS_OFFSET_XCR0 EQU 170h
    ; @brief defines the offset of state_save_t.dr0
    SS_OFFSET_DR0 EQU 1C0h
    ; @brief defines the offset of state_save_t.dr1
    SS_OFFSET_DR1 EQU 1C8h
    ; @brief defines the offset of state_save_t.dr2
    SS_OFFSET_DR2 EQU 1D0h
    ; @brief defines the offset of state_save_t.dr3
    SS_OFFSET_DR3 EQU 1D8h
    ; @brief defines the offset of state_save_t.dr6
    SS_OFFSET_DR6 EQU 1F0h
    ; @brief defines the offset of state_save_t.dr7
    SS_OFFSET_DR7 EQU 1F8h
    ; @brief defines the offset of state_save_t.efer
    SS_OFFSET_EFER EQU 240h
    ; @brief defines the offset of state_save_t.star
    SS_OFFSET_STAR EQU 248h
    ; @brief defines the offset of state_save_t.lstar
    SS_OFFSET_LSTAR EQU 250h
    ; @brief defines the offset of state_save_t.cstar
    SS_OFFSET_CSTAR EQU 258h
    ; @brief defines the offset of state_save_t.fmask
    SS_OFFSET_FMASK EQU 260h
    ; @brief defines the offset of state_save_t.fs_base
    SS_OFFSET_FS_BASE EQU 268h
    ; @brief defines the offset of state_save_t.gs_base
    SS_OFFSET_GS_BASE EQU 270h
    ; @brief defines the offset of state_save_t.kernel_gs_base
    SS_OFFSET_KERNEL_GS_BASE EQU 278h
    ; @brief defines the offset of state_save_t.sysenter_cs
    SS_OFFSET_SYSENTER_CS EQU 280h
    ; @brief defines the offset of state_save_t.sysenter_esp
    SS_OFFSET_SYSENTER_ESP EQU 288h
    ; @brief defines the offset of state_save_t.sysenter_eip
    SS_OFFSET_SYSENTER_EIP EQU 290h
    ; @brief defines the offset of state_save_t.pat
    SS_OFFSET_PAT EQU 298h
    ; @brief defines the offset of state_save_t.debugctl
    SS_OFFSET_DEBUGCTL EQU 2A0h

    ; @brief defines MSR_SYSENTER_CS
    MSR_SYSENTER_CS EQU 00000174h
    ; @brief defines MSR_SYSENTER_ESP
    MSR_SYSENTER_ESP EQU 00000175h
    ; @brief defines MSR_SYSENTER_EIP
    MSR_SYSENTER_EIP EQU 00000176h
    ; @brief defines MSR_DEBUGCTL
    MSR_DEBUGCTL EQU 000001D9h
    ; @brief defines MSR_PAT
    MSR_PAT EQU 00000277h
    ; @brief defines MSR_EFER
    MSR_EFER EQU 0C0000080h
    ; @brief defines MSR_STAR
    MSR_STAR EQU 0C0000081h
    ; @brief defines MSR_LSTAR
    MSR_LSTAR EQU 0C0000082h
    ; @brief defines MSR_CSTAR
    MSR_CSTAR EQU 0C0000083h
    ; @brief defines MSR_FMASK
    MSR_FMASK EQU 0C0000084h
    ; @brief defines MSR_FS_BASE
    MSR_FS_BASE EQU 0C0000100h
    ; @brief defines MSR_GS_BASE
    MSR_GS_BASE EQU 0C0000101h
    ; @brief defines MSR_KERNEL_GS_BASE
    MSR_KERNEL_GS_BASE EQU 0C0000102h

    enable_interrupts PROTO
    disable_interrupts PROTO

    demote_text SEGMENT ALIGN(1000h) 'CODE'
    demote PROC

    ; **************************************************************************
    ; Report Success On Completion
    ; **************************************************************************

    xor rax, rax

    ; **************************************************************************
    ; General Purpose Registers
    ; **************************************************************************

    mov [r8 + SS_OFFSET_RAX], rax
    mov [r8 + SS_OFFSET_RBX], rbx
    mov [r8 + SS_OFFSET_RCX], rcx
    mov [r8 + SS_OFFSET_RDX], rdx
    mov [r8 + SS_OFFSET_RBP], rbp
    mov [r8 + SS_OFFSET_RSI], rsi
    mov [r8 + SS_OFFSET_RDI], rdi
    mov [r8 + SS_OFFSET_R8], r8
    mov [r8 + SS_OFFSET_R9], r9
    mov [r8 + SS_OFFSET_R10], r10
    mov [r8 + SS_OFFSET_R11], r11
    mov [r8 + SS_OFFSET_R12], r12
    mov [r8 + SS_OFFSET_R13], r13
    mov [r8 + SS_OFFSET_R14], r14
    mov [r8 + SS_OFFSET_R15], r15

    lea rax, [demotion_return]
    mov [r8 + SS_OFFSET_RIP], rax
    mov [r8 + SS_OFFSET_RSP], rsp

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
    pop qword ptr[r15 + SS_OFFSET_RFLAGS]
    push qword ptr[r14 + SS_OFFSET_RFLAGS]
    popfq

    ; **************************************************************************
    ; IDT
    ; **************************************************************************

    call disable_interrupts

    sidt fword ptr[r15 + SS_OFFSET_IDTR]
    lidt fword ptr[r14 + SS_OFFSET_IDTR]

    ; **************************************************************************
    ; MSRs
    ; **************************************************************************

    mov ecx, MSR_EFER
    rdmsr
    mov [r15 + SS_OFFSET_EFER + 0h], eax
    mov [r15 + SS_OFFSET_EFER + 4h], edx
    mov eax, [r14 + SS_OFFSET_EFER + 0h]
    mov edx, [r14 + SS_OFFSET_EFER + 4h]
    wrmsr

    mov ecx, MSR_STAR
    rdmsr
    mov [r15 + SS_OFFSET_STAR + 0h], eax
    mov [r15 + SS_OFFSET_STAR + 4h], edx
    mov eax, [r14 + SS_OFFSET_STAR + 0h]
    mov edx, [r14 + SS_OFFSET_STAR + 4h]
    wrmsr

    mov ecx, MSR_LSTAR
    rdmsr
    mov [r15 + SS_OFFSET_LSTAR + 0h], eax
    mov [r15 + SS_OFFSET_LSTAR + 4h], edx
    mov eax, [r14 + SS_OFFSET_LSTAR + 0h]
    mov edx, [r14 + SS_OFFSET_LSTAR + 4h]
    wrmsr

    mov ecx, MSR_CSTAR
    rdmsr
    mov [r15 + SS_OFFSET_CSTAR + 0h], eax
    mov [r15 + SS_OFFSET_CSTAR + 4h], edx
    mov eax, [r14 + SS_OFFSET_CSTAR + 0h]
    mov edx, [r14 + SS_OFFSET_CSTAR + 4h]
    wrmsr

    mov ecx, MSR_FMASK
    rdmsr
    mov [r15 + SS_OFFSET_FMASK + 0h], eax
    mov [r15 + SS_OFFSET_FMASK + 4h], edx
    mov eax, [r14 + SS_OFFSET_FMASK + 0h]
    mov edx, [r14 + SS_OFFSET_FMASK + 4h]
    wrmsr

    mov ecx, MSR_FS_BASE
    rdmsr
    mov [r15 + SS_OFFSET_FS_BASE + 0h], eax
    mov [r15 + SS_OFFSET_FS_BASE + 4h], edx
    mov eax, [r14 + SS_OFFSET_FS_BASE + 0h]
    mov edx, [r14 + SS_OFFSET_FS_BASE + 4h]
    wrmsr

    mov ecx, MSR_GS_BASE
    rdmsr
    mov [r15 + SS_OFFSET_GS_BASE + 0h], eax
    mov [r15 + SS_OFFSET_GS_BASE + 4h], edx
    mov eax, [r14 + SS_OFFSET_GS_BASE + 0h]
    mov edx, [r14 + SS_OFFSET_GS_BASE + 4h]
    wrmsr

    mov ecx, MSR_KERNEL_GS_BASE
    rdmsr
    mov [r15 + SS_OFFSET_KERNEL_GS_BASE + 0h], eax
    mov [r15 + SS_OFFSET_KERNEL_GS_BASE + 4h], edx
    mov eax, [r14 + SS_OFFSET_KERNEL_GS_BASE + 0h]
    mov edx, [r14 + SS_OFFSET_KERNEL_GS_BASE + 4h]
    wrmsr

    mov ecx, MSR_SYSENTER_CS
    rdmsr
    mov [r15 + SS_OFFSET_SYSENTER_CS + 0h], eax
    mov [r15 + SS_OFFSET_SYSENTER_CS + 4h], edx
    mov eax, [r14 + SS_OFFSET_SYSENTER_CS + 0h]
    mov edx, [r14 + SS_OFFSET_SYSENTER_CS + 4h]
    wrmsr

    mov ecx, MSR_SYSENTER_ESP
    rdmsr
    mov [r15 + SS_OFFSET_SYSENTER_ESP + 0h], eax
    mov [r15 + SS_OFFSET_SYSENTER_ESP + 4h], edx
    mov eax, [r14 + SS_OFFSET_SYSENTER_ESP + 0h]
    mov edx, [r14 + SS_OFFSET_SYSENTER_ESP + 4h]
    wrmsr

    mov ecx, MSR_SYSENTER_EIP
    rdmsr
    mov [r15 + SS_OFFSET_SYSENTER_EIP + 0h], eax
    mov [r15 + SS_OFFSET_SYSENTER_EIP + 4h], edx
    mov eax, [r14 + SS_OFFSET_SYSENTER_EIP + 0h]
    mov edx, [r14 + SS_OFFSET_SYSENTER_EIP + 4h]
    wrmsr

    mov ecx, MSR_PAT
    rdmsr
    mov [r15 + SS_OFFSET_PAT + 0h], eax
    mov [r15 + SS_OFFSET_PAT + 4h], edx
    mov eax, [r14 + SS_OFFSET_PAT + 0h]
    mov edx, [r14 + SS_OFFSET_PAT + 4h]
    wrmsr

    mov ecx, MSR_DEBUGCTL
    rdmsr
    mov [r15 + SS_OFFSET_DEBUGCTL + 0h], eax
    mov [r15 + SS_OFFSET_DEBUGCTL + 4h], edx
    mov eax, [r14 + SS_OFFSET_DEBUGCTL + 0h]
    mov edx, [r14 + SS_OFFSET_DEBUGCTL + 4h]
    wrmsr

    ; **************************************************************************
    ; GDT
    ; **************************************************************************

    sgdt fword ptr[r15 + SS_OFFSET_GDTR]
    lgdt fword ptr[r14 + SS_OFFSET_GDTR]

    mov dx, es
    mov [r15 + SS_OFFSET_ES_SELECTOR], dx
    mov dx, [r14 + SS_OFFSET_ES_SELECTOR]
    mov es, dx

    mov dx, cs
    mov [r15 + SS_OFFSET_CS_SELECTOR], dx
    mov ax, [r14 + SS_OFFSET_CS_SELECTOR]
    push rax

    mov dx, ss
    mov [r15 + SS_OFFSET_SS_SELECTOR], dx
    mov dx, [r14 + SS_OFFSET_SS_SELECTOR]
    mov ss, dx

    mov dx, ds
    mov [r15 + SS_OFFSET_DS_SELECTOR], dx
    mov dx, [r14 + SS_OFFSET_DS_SELECTOR]
    mov ds, dx

    mov dx, fs
    mov [r15 + SS_OFFSET_FS_SELECTOR], dx
    mov dx, [r14 + SS_OFFSET_FS_SELECTOR]
    mov fs, dx

    mov dx, gs
    mov [r15 + SS_OFFSET_GS_SELECTOR], dx
    mov dx, [r14 + SS_OFFSET_GS_SELECTOR]
    mov gs, dx

    sldt dx
    mov [r15 + SS_OFFSET_LDTR_SELECTOR], dx
    mov dx, [r14 + SS_OFFSET_LDTR_SELECTOR]
    lldt dx

    str dx
    mov [r15 + SS_OFFSET_TR_SELECTOR], dx
    mov dx, [r14 + SS_OFFSET_TR_SELECTOR]
    ltr dx

    lea rax, [gdt_and_cs_loaded]
    push rax

    retfq

gdt_and_cs_loaded:

    ; **************************************************************************
    ; Control Registers
    ; **************************************************************************

    mov rax, cr0
    mov [r15 + SS_OFFSET_CR0], rax
    mov rax, [r14 + SS_OFFSET_CR0]
    mov cr0, rax

    mov rax, cr2
    mov [r15 + SS_OFFSET_CR2], rax
    mov rax, [r14 + SS_OFFSET_CR2]
    mov cr2, rax

    mov rax, cr4
    mov [r15 + SS_OFFSET_CR4], rax
    mov rax, [r14 + SS_OFFSET_CR4]
    mov cr4, rax

    mov rax, cr3
    mov [r15 + SS_OFFSET_CR3], rax
    mov rax, [r14 + SS_OFFSET_CR3]
    mov cr3, rax

    mov rax, cr8
    mov [r15 + SS_OFFSET_CR8], rax
    mov rax, [r14 + SS_OFFSET_CR8]
    mov cr8, rax

    xor ecx, ecx
    xgetbv
    mov [r15 + SS_OFFSET_XCR0 + 0h], eax
    mov [r15 + SS_OFFSET_XCR0 + 4h], edx
    mov eax, [r14 + SS_OFFSET_XCR0 + 0h]
    mov edx, [r14 + SS_OFFSET_XCR0 + 4h]
    xsetbv

    ; **************************************************************************
    ; Stack
    ; **************************************************************************

    mov rsp, [r14 + SS_OFFSET_RSP]

    ; **************************************************************************
    ; Debug Registers
    ; **************************************************************************

    mov rax, dr0
    mov [r15 + SS_OFFSET_DR0], rax
    mov rax, [r14 + SS_OFFSET_DR0]
    mov dr0, rax

    mov rax, dr1
    mov [r15 + SS_OFFSET_DR1], rax
    mov rax, [r14 + SS_OFFSET_DR1]
    mov dr1, rax

    mov rax, dr2
    mov [r15 + SS_OFFSET_DR2], rax
    mov rax, [r14 + SS_OFFSET_DR2]
    mov dr2, rax

    mov rax, dr3
    mov [r15 + SS_OFFSET_DR3], rax
    mov rax, [r14 + SS_OFFSET_DR3]
    mov dr3, rax

    mov rax, dr6
    mov [r15 + SS_OFFSET_DR6], rax
    mov rax, [r14 + SS_OFFSET_DR6]
    mov dr6, rax

    mov rax, dr7
    mov [r15 + SS_OFFSET_DR7], rax
    mov rax, [r14 + SS_OFFSET_DR7]
    mov dr7, rax

    ; **************************************************************************
    ; Call Microkernel
    ; **************************************************************************

    mov rdi, r13
    push qword ptr[r14 + SS_OFFSET_RIP]
    ret
    int 3

demotion_return:


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
