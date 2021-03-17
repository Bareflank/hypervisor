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

    promote_text SEGMENT ALIGN(1000h) 'CODE'
    promote PROC

    ; **************************************************************************
    ; Debug Registers
    ; **************************************************************************

    mov rax, [r15 + 1F8h]
    mov dr7, rax

    mov rax, [r15 + 1F0h]
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

    mov rax, [r15 + 158h]
    and rax, 0FFFFFFFFFFFFF000h
    mov cr3, rax

    mov rax, [r15 + 160h]
    and rax, 0FFFFFFFFFFFFFF7Fh
    mov cr4, rax

    mov rax, [r15 + 158h]
    mov cr3, rax

    mov rax, [r15 + 160h]
    mov cr4, rax

    mov rax, [r15 + 150h]
    mov cr2, rax

    mov rax, [r15 + 140h]
    mov cr0, rax

    mov rsp, [r15 + 080h]

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

    lgdt fword ptr[r15 + 0A0h]

    mov dx, [r15 + 0C0h]
    mov es, dx

    mov ax, [r15 + 0D0h]
    push rax

    mov dx, [r15 + 0E0h]
    mov ss, dx

    mov dx, [r15 + 0F0h]
    mov ds, dx

    mov dx, [r15 + 100h]
    mov fs, dx

    mov dx, [r15 + 110h]
    mov gs, dx

    mov dx, [r15 + 120h]
    lldt dx

    mov dx, [r15 + 130h]
    ltr dx

    lea rax, [gdt_and_cs_loaded]
    push rax

    retfq

gdt_and_cs_loaded:

    ; **************************************************************************
    ; MSRs
    ; **************************************************************************

    mov ecx, 000001D9h      ; DEBUGCTL
    mov eax, [r15 + 2A0h]
    mov edx, [r15 + 2A4h]
    wrmsr

    mov ecx, 00000277h      ; PAT
    mov eax, [r15 + 298h]
    mov edx, [r15 + 29Ch]
    wrmsr

    mov ecx, 00000176h      ; SYSENTER_EIP
    mov eax, [r15 + 290h]
    mov edx, [r15 + 294h]
    wrmsr

    mov ecx, 00000175h      ; SYSENTER_ESP
    mov eax, [r15 + 288h]
    mov edx, [r15 + 28Ch]
    wrmsr

    mov ecx, 00000174h      ; SYSENTER_CS
    mov eax, [r15 + 280h]
    mov edx, [r15 + 284h]
    wrmsr

    mov ecx, 0C0000102h      ; Kernel GS Base
    mov eax, [r15 + 278h]
    mov edx, [r15 + 27Ch]
    wrmsr

    mov ecx, 0C0000101h      ; GS Base
    mov eax, [r15 + 270h]
    mov edx, [r15 + 274h]
    wrmsr

    mov ecx, 0C0000100h      ; FS Base
    mov eax, [r15 + 268h]
    mov edx, [r15 + 26Ch]
    wrmsr

    mov ecx, 0C0000084h      ; FMASK
    mov eax, [r15 + 260h]
    mov edx, [r15 + 264h]
    wrmsr

    mov ecx, 0C0000083h      ; CSTAR
    mov eax, [r15 + 258h]
    mov edx, [r15 + 25Ch]
    wrmsr

    mov ecx, 0C0000082h      ; LSTAR
    mov eax, [r15 + 250h]
    mov edx, [r15 + 254h]
    wrmsr

    mov ecx, 0C0000081h      ; STAR
    mov eax, [r15 + 248h]
    mov edx, [r15 + 24Ch]
    wrmsr

    mov ecx, 0C0000080h      ; EFER
    mov eax, [r15 + 240h]
    mov edx, [r15 + 244h]
    wrmsr

    ; **************************************************************************
    ; IDT
    ; **************************************************************************

    lidt fword ptr[r15 + 0B0h]

    ; **************************************************************************
    ; NMIs
    ; **************************************************************************

    mov rax, [r15 + 318h]
    cmp rax, 1h
    jne nmis_complete

    int 2

nmis_complete:

    ; **************************************************************************
    ; Flags
    ; **************************************************************************

    push [r15 + 088h]
    popfq

    ; **************************************************************************
    ; General Purpose Registers
    ; **************************************************************************

    mov rax, [r15 + 078h]
    push rax

    mov r14, [r15 + 068h]
    mov r13, [r15 + 060h]
    mov r12, [r15 + 058h]
    mov r11, [r15 + 050h]
    mov r10, [r15 + 048h]
    mov r9,  [r15 + 040h]
    mov r8,  [r15 + 038h]
    mov rdi, [r15 + 030h]
    mov rsi, [r15 + 028h]
    mov rbp, [r15 + 020h]
    mov rdx, [r15 + 018h]
    mov rcx, [r15 + 010h]
    mov rbx, [r15 + 008h]
    mov rax, [r15 + 000h]

    mov r15, [r15 + 070h]

    call enable_interrupts
    ret
    int 3

    promote ENDP
    promote_text ENDS
    end
