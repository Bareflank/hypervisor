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

global __halt:function
global __stop:function
global __invd:function
global __wbinvd:function
global __cpuid_eax:function
global __cpuid_ebx:function
global __cpuid_ecx:function
global __cpuid_edx:function
global __cpuid:function
global __read_rflags:function
global __read_msr:function
global __write_msr:function
global __read_rip:function
global __read_cr0:function
global __write_cr0:function
global __read_cr3:function
global __write_cr3:function
global __read_cr4:function
global __write_cr4:function
global __read_xcr0:function
global __write_xcr0:function
global __read_dr7:function
global __write_dr7:function
global __read_es:function
global __write_es:function
global __read_cs:function
global __write_cs:function
global __read_ss:function
global __write_ss:function
global __read_ds:function
global __write_ds:function
global __read_fs:function
global __write_fs:function
global __read_gs:function
global __write_gs:function
global __read_tr:function
global __write_tr:function
global __read_ldtr:function
global __write_ldtr:function
global __read_rsp:function
global __read_gdt:function
global __write_gdt:function
global __read_idt:function
global __write_idt:function
global __outb:function
global __inb:function
global __outw:function
global __inw:function

section .text

; void __halt(void)
__halt:
    hlt

; void __stop(void)
__stop:
    cli
    hlt

; void __invd(void)
__invd:
    invd
    ret

; void __wbinvd(void)
__wbinvd:
    wbinvd
    ret

; uint32_t cpuid_eax(uint32_t val)
__cpuid_eax:
    push rbx

    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    xor rdx, rdx

    mov eax, edi
    cpuid

    pop rbx
    ret

; uint32_t cpuid_ebx(uint32_t val)
__cpuid_ebx:
    push rbx

    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    xor rdx, rdx

    mov eax, edi
    cpuid
    mov eax, ebx

    pop rbx
    ret

; uint32_t cpuid_ecx(uint32_t val)
__cpuid_ecx:
    push rbx

    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    xor rdx, rdx

    mov eax, edi
    cpuid
    mov eax, ecx

    pop rbx
    ret

; uint32_t cpuid_edx(uint32_t val)
__cpuid_edx:
    push rbx

    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    xor rdx, rdx

    mov eax, edi
    cpuid
    mov eax, edx

    pop rbx
    ret

; void __cpuid(uint64_t *rax,
;              uint64_t *rbx,
;              uint64_t *rcx,
;              uint64_t *rdx);
__cpuid:
    push rbx

    mov r8, rdi
    mov r9, rsi
    mov r10, rdx
    mov r11, rcx

    mov rax, [r8]
    mov rbx, [r9]
    mov rcx, [r10]
    mov rdx, [r11]

    cpuid

    mov [r8], rax
    mov [r9], rbx
    mov [r10], rcx
    mov [r11], rdx

    mov rax, 0

    pop rbx
    ret

; uint64_t read_rflags(void)
__read_rflags:
    pushfq
    pop rax
    ret

; uint64_t __read_msr(uint32_t msr)
__read_msr:
    mov rcx, rdi
    rdmsr
    shl rdx, 32
    or rax, rdx

    ret

; void __write_msr(uint32_t msr, uint64_t val)
__write_msr:
    mov rax, rsi
    mov rdx, rsi
    shr rdx, 32
    mov rcx, rdi
    wrmsr

    ret

; uint64_t __read_rip(void)
__read_rip:
    lea rax, [rel $]
    ret

; uint64_t __read_cr0(void)
__read_cr0:
    mov rax, cr0
    ret

; void __write_cr0(uint64_t val)
__write_cr0:
    mov cr0, rdi
    ret

; uint64_t __read_cr3(void)
__read_cr3:
    mov rax, cr3
    ret

; void __write_cr3(uint64_t val)
__write_cr3:
    mov cr3, rdi
    ret

; uint64_t __read_cr4(void)
__read_cr4:
    mov rax, cr4
    ret

; void __write_cr4(uint64_t val)
__write_cr4:
    mov cr4, rdi
    ret

; uint64_t __read_xcr0(void)
__read_xcr0:
    mov rcx, 0
    xgetbv
    shl rdx, 32
    or rax, rdx
    ret

; void __write_xcr0(uint64_t val)
__write_xcr0:
    mov rax, rdi
    mov rdx, rdi
    shr rdx, 32
    mov rcx, 0
    xsetbv
    ret

; uint64_t __read_dr7(void)
__read_dr7:
    mov rax, dr7
    ret

; void __write_dr7(uint64_t val)
__write_dr7:
    mov dr7, rdi
    ret

; uint16_t __read_es(void)
__read_es:
    xor rax, rax
    mov ax, es
    ret

; void __write_es(uint16_t val)
__write_es:
    xor rax, rax
    mov es, di
    ret

; uint16_t __read_cs(void)
__read_cs:
    xor rax, rax
    mov ax, cs
    ret

; void __write_cs(uint16_t val)
;
; The added 0x48 is an undocumented issue with NASM. Basically, even though
; BITS 64 is used, and we are compiling for 64bit, NASM does not add the
; REX prefix to the retf instruction. As a result, we need to hand jam it in,
; otherwise NASM will compile a 32bit instruction, and the data on the stack
; will be wrong
__write_cs:
    pop rax
    push di
    push rax
    db 0x48
    retf

; uint16_t __read_ss(void)
__read_ss:
    xor rax, rax
    mov ax, ss
    ret

; void __write_ss(uint16_t val)
__write_ss:
    mov ss, di
    ret

; uint16_t __read_ds(void)
__read_ds:
    xor rax, rax
    mov ax, ds
    ret

; void __write_ds(uint16_t val)
__write_ds:
    mov ds, di
    ret

; uint16_t __read_fs(void)
__read_fs:
    xor rax, rax
    mov ax, fs
    ret

; void __write_fs(uint16_t val)
__write_fs:
    mov fs, di
    ret

; uint16_t __read_gs(void)
__read_gs:
    xor rax, rax
    mov ax, gs
    ret

; void __write_gs(uint16_t val)
__write_gs:
    mov gs, di
    ret

; uint16_t __read_tr(void)
__read_tr:
    xor rax, rax
    str ax
    ret

; void __write_tr(uint16_t val)
__write_tr:
    ltr di
    ret

; uint16_t __read_ldtr(void)
__read_ldtr:
    xor rax, rax
    sldt ax
    ret

; void __write_ldtr(uint16_t val)
__write_ldtr:
    lldt di
    ret

; uint64_t __read_rsp(void)
__read_rsp:
    mov rax, rsp
    ret

; void __read_gdt(void *gdt)
__read_gdt:
    sgdt [rdi]
    ret

; void __write_gdt(void *gdt)
__write_gdt:
    lgdt [rdi]
    ret

; void __read_idt(void *idt)
__read_idt:
    sidt [rdi]
    ret

; void __write_idt(void *idt)
__write_idt:
    lidt [rdi]
    ret

; void __outb(uint8_t port, uint16_t val)
__outb:
    mov dx, di
    mov ax, si
    out dx, al
	ret

; void __outw(uint16_t port, uint16_t val)
__outw:
	mov dx, di
    mov ax, si
	out dx, ax
	ret

; uint8_t __inb(uint16_t port)
__inb:
	xor rax, rax
	mov dx, di
	in al, dx
	ret

; uint16_t __inw(uint16_t port)
__inw:
    xor rax, rax
    mov dx, di
	in ax, dx
	ret
