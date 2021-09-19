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
    ; @brief defines the offset of state_save_t.nmi
    SS_OFFSET_NMI EQU 318h

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

    promote_text SEGMENT ALIGN(1000h) 'CODE'
    promote PROC

    ; **************************************************************************
    ; Debug Registers
    ; **************************************************************************

    mov rax, [r15 + SS_OFFSET_DR7]
    mov dr7, rax

    mov rax, [r15 + SS_OFFSET_DR6]
    mov dr6, rax

    ; **************************************************************************
    ; Control Registers
    ; **************************************************************************

    ; Notes:
    ; - When we promote the OS, we need to handle PCID properly. This is
    ;   done by clearing PCID in CR3, setting CR4 and then putting the actual
    ;   CR3 value into CR3. That's why we set CR3 twice here.
    ; - We also need to handle global paging properly. Once we got back to
    ;   the OS, pages from the microkernel should be flushed from the TLB.
    ;   The safest way to do that is to clear the global paging bit which
    ;   will do a complete TLB flush.
    ; - Finally, we need to load a new stack pointer once we load the new
    ;   CR3 so that we can push/pop as needed

    mov rax, [r15 + SS_OFFSET_CR3]
    and rax, 0FFFFFFFFFFFFF000h
    mov cr3, rax

    mov rax, [r15 + SS_OFFSET_CR4]
    and rax, 0FFFFFFFFFFFFFF7Fh
    mov cr4, rax

    mov rax, [r15 + SS_OFFSET_CR3]
    mov cr3, rax

    mov rax, [r15 + SS_OFFSET_CR4]
    mov cr4, rax

    mov rax, [r15 + SS_OFFSET_CR2]
    mov cr2, rax

    mov rax, [r15 + SS_OFFSET_CR0]
    mov cr0, rax

    ; **************************************************************************
    ; Stack
    ; **************************************************************************

    mov rsp, [r15 + SS_OFFSET_RSP]

    ; **************************************************************************
    ; Clear TSS Busy
    ; **************************************************************************

    ; NOTE:
    ; - The TR in the GDT used by the root OS is marked as busy, and as
    ;   a result, cannot be loaded without first marking it as available.
    ; - Some OS's like Linux mark the GDT as read-only, and will not provide
    ;   the physical address of the GDT, which means the microkernel needs
    ;   to walk the root OS's page tables to locate the physical address
    ;   and then map it into the microkernel's page tables. Once this is
    ;   done, we can clear the TSS busy bit. If the microkernel fails to
    ;   perform at least this operation, it will halt with no means to
    ;   return as it cannot promote the GDT portion of the root OS's state.

    mov rdx, [r15 + 0A2h]

    xor rax, rax
    mov ax, [r15 + 130h]

    add rdx, rax

    mov rax, 0FFFFFDFFFFFFFFFFh
    and [rdx], rax

    ; **************************************************************************
    ; GDT
    ; **************************************************************************

    ; Notes:
    ; - Before we can restore the GDT, we need to clear the TSS Busy bit. This
    ;   is because the TSS that the OS was using was busy when it was replaced
    ;   and you cannot load TR with a segment descriptor that is marked as
    ;   busy.
    ; - To clear the TSS Busy bit we must get the address of the GDT and
    ;   then use the TR selector to get the TSS segment descriptor and clear
    ;   the TSS Busy bit. This way, when TR is loaded, it is loaded with
    ;   a properly set up TSS segment descriptor.
    ; - On Linux, the GDT is marked usually as read-only, so there is code
    ;   in the platform logic to mark the GDT as read/write just in case
    ;   this code needs to execute.

    lgdt fword ptr[r15 + SS_OFFSET_GDTR]

    mov dx, [r15 + SS_OFFSET_ES_SELECTOR]
    mov es, dx

    mov ax, [r15 + SS_OFFSET_CS_SELECTOR]
    push rax

    mov dx, [r15 + SS_OFFSET_SS_SELECTOR]
    mov ss, dx

    mov dx, [r15 + SS_OFFSET_DS_SELECTOR]
    mov ds, dx

    mov dx, [r15 + SS_OFFSET_FS_SELECTOR]
    mov fs, dx

    mov dx, [r15 + SS_OFFSET_GS_SELECTOR]
    mov gs, dx

    mov dx, [r15 + SS_OFFSET_LDTR_SELECTOR]
    lldt dx

    mov dx, [r15 + SS_OFFSET_TR_SELECTOR]
    ltr dx

    lea rax, [gdt_and_cs_loaded]
    push rax

    retfq

gdt_and_cs_loaded:

    ; **************************************************************************
    ; MSRs
    ; **************************************************************************

    mov ecx, MSR_DEBUGCTL
    mov eax, [r15 + SS_OFFSET_DEBUGCTL + 0h]
    mov edx, [r15 + SS_OFFSET_DEBUGCTL + 4h]
    wrmsr

    mov ecx, MSR_PAT
    mov eax, [r15 + SS_OFFSET_PAT + 0h]
    mov edx, [r15 + SS_OFFSET_PAT + 4h]
    wrmsr

    mov ecx, MSR_SYSENTER_EIP
    mov eax, [r15 + SS_OFFSET_SYSENTER_EIP + 0h]
    mov edx, [r15 + SS_OFFSET_SYSENTER_EIP + 4h]
    wrmsr

    mov ecx, MSR_SYSENTER_EIP
    mov eax, [r15 + SS_OFFSET_SYSENTER_EIP + 0h]
    mov edx, [r15 + SS_OFFSET_SYSENTER_EIP + 4h]
    wrmsr

    mov ecx, MSR_SYSENTER_CS
    mov eax, [r15 + SS_OFFSET_SYSENTER_CS + 0h]
    mov edx, [r15 + SS_OFFSET_SYSENTER_CS + 4h]
    wrmsr

    mov ecx, MSR_KERNEL_GS_BASE
    mov eax, [r15 + SS_OFFSET_KERNEL_GS_BASE + 0h]
    mov edx, [r15 + SS_OFFSET_KERNEL_GS_BASE + 4h]
    wrmsr

    mov ecx, MSR_GS_BASE
    mov eax, [r15 + SS_OFFSET_GS_BASE + 0h]
    mov edx, [r15 + SS_OFFSET_GS_BASE + 4h]
    wrmsr

    mov ecx, MSR_FS_BASE
    mov eax, [r15 + SS_OFFSET_FS_BASE + 0h]
    mov edx, [r15 + SS_OFFSET_FS_BASE + 4h]
    wrmsr

    mov ecx, MSR_FMASK
    mov eax, [r15 + SS_OFFSET_FMASK + 0h]
    mov edx, [r15 + SS_OFFSET_FMASK + 4h]
    wrmsr

    mov ecx, MSR_CSTAR
    mov eax, [r15 + SS_OFFSET_CSTAR + 0h]
    mov edx, [r15 + SS_OFFSET_CSTAR + 4h]
    wrmsr

    mov ecx, MSR_LSTAR
    mov eax, [r15 + SS_OFFSET_LSTAR + 0h]
    mov edx, [r15 + SS_OFFSET_LSTAR + 4h]
    wrmsr

    mov ecx, MSR_STAR
    mov eax, [r15 + SS_OFFSET_STAR + 0h]
    mov edx, [r15 + SS_OFFSET_STAR + 4h]
    wrmsr

    mov ecx, MSR_EFER
    mov eax, [r15 + SS_OFFSET_EFER + 0h]
    mov edx, [r15 + SS_OFFSET_EFER + 4h]
    wrmsr

    ; **************************************************************************
    ; IDT
    ; **************************************************************************

    lidt fword ptr[r15 + SS_OFFSET_IDTR]

    ; **************************************************************************
    ; NMIs
    ; **************************************************************************

    mov rax, [r15 + SS_OFFSET_NMI]
    cmp rax, 1h
    jne nmis_complete

    int 2

nmis_complete:

    ; **************************************************************************
    ; Flags
    ; **************************************************************************

    push qword ptr[r15 + SS_OFFSET_RFLAGS]
    popfq

    ; **************************************************************************
    ; General Purpose Registers
    ; **************************************************************************

    mov rax, [r15 + SS_OFFSET_RIP]
    push rax

    mov r14, [r15 + SS_OFFSET_R14]
    mov r13, [r15 + SS_OFFSET_R13]
    mov r12, [r15 + SS_OFFSET_R12]
    mov r11, [r15 + SS_OFFSET_R11]
    mov r10, [r15 + SS_OFFSET_R10]
    mov r9,  [r15 + SS_OFFSET_R9]
    mov r8,  [r15 + SS_OFFSET_R8]
    mov rdi, [r15 + SS_OFFSET_RDI]
    mov rsi, [r15 + SS_OFFSET_RSI]
    mov rbp, [r15 + SS_OFFSET_RBP]
    mov rdx, [r15 + SS_OFFSET_RDX]
    mov rcx, [r15 + SS_OFFSET_RCX]
    mov rbx, [r15 + SS_OFFSET_RBX]
    mov rax, [r15 + SS_OFFSET_RAX]

    mov r15, [r15 + SS_OFFSET_R15]

    call enable_interrupts
    ret
    int 3

    promote ENDP
    promote_text ENDS
    end
