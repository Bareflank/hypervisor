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

bits 64
default rel

section .text

global __halt:function
__halt:
    hlt

global __stop:function
__stop:
    cli
    hlt

global __invd:function
__invd:
    invd
    ret

global __wbinvd:function
__wbinvd:
    wbinvd
    ret

global __cpuid_eax:function
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

global __cpuid_ebx:function
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

global __cpuid_ecx:function
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

global __cpuid_edx:function
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

global __cpuid:function
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

global __read_rflags:function
__read_rflags:
    pushfq
    pop rax
    ret

global __write_rflags:function
__write_rflags:
    push rdi
    popf
    ret

global __read_msr:function
__read_msr:
    mov rcx, rdi
    rdmsr
    shl rdx, 32
    or rax, rdx

    ret

global __write_msr:function
__write_msr:
    mov rax, rsi
    mov rdx, rsi
    shr rdx, 32
    mov rcx, rdi
    wrmsr

    ret

global __read_cr0:function
__read_cr0:
    mov rax, cr0
    ret

global __write_cr0:function
__write_cr0:
    mov cr0, rdi
    ret

global __read_cr3:function
__read_cr3:
    mov rax, cr3
    ret

global __write_cr3:function
__write_cr3:
    mov cr3, rdi
    ret

global __read_cr4:function
__read_cr4:
    mov rax, cr4
    ret

global __write_cr4:function
__write_cr4:
    mov cr4, rdi
    ret

global __read_dr7:function
__read_dr7:
    mov rax, dr7
    ret

global __write_dr7:function
__write_dr7:
    mov dr7, rdi
    ret

global __read_es:function
__read_es:
    xor rax, rax
    mov ax, es
    ret

global __write_es:function
__write_es:
    xor rax, rax
    mov es, di
    ret

global __read_cs:function
__read_cs:
    xor rax, rax
    mov ax, cs
    ret

global __write_cs:function
__write_cs:

    ; The added 0x48 is an undocumented issue with NASM. Basically, even though
    ; BITS 64 is used, and we are compiling for 64bit, NASM does not add the
    ; REX prefix to the retf instruction. As a result, we need to hand jam it
    ; in otherwise NASM will compile a 32bit instruction, and the data on the
    ; stack will be wrong

    pop rax
    push di
    push rax
    db 0x48
    retf

global __read_ss:function
__read_ss:
    xor rax, rax
    mov ax, ss
    ret

global __write_ss:function
__write_ss:
    mov ss, di
    ret

global __read_ds:function
__read_ds:
    xor rax, rax
    mov ax, ds
    ret

global __write_ds:function
__write_ds:
    mov ds, di
    ret

global __read_fs:function
__read_fs:
    xor rax, rax
    mov ax, fs
    ret

global __write_fs:function
__write_fs:
    mov fs, di
    ret

global __read_gs:function
__read_gs:
    xor rax, rax
    mov ax, gs
    ret

global __write_gs:function
__write_gs:
    mov gs, di
    ret

global __read_ldtr:function
__read_ldtr:
    xor rax, rax
    sldt ax
    ret

global __write_ldtr:function
__write_ldtr:
    lldt di
    ret

global __read_tr:function
__read_tr:
    xor rax, rax
    str ax
    ret

global __write_tr:function
__write_tr:
    ltr di
    ret

global __read_gdt:function
__read_gdt:
    sgdt [rdi]
    ret

global __write_gdt:function
__write_gdt:
    lgdt [rdi]
    ret

global __read_idt:function
__read_idt:
    sidt [rdi]
    ret

global __write_idt:function
__write_idt:
    lidt [rdi]
    ret

global __inb:function
__inb:
    xor rax, rax
    mov dx, di
    in al, dx
    ret

global __inw:function
__inw:
    xor rax, rax
    mov dx, di
    in ax, dx
    ret

global __outb:function
__outb:
    mov dx, di
    mov ax, si
    out dx, al
	ret

global __outw:function
__outw:
	mov dx, di
    mov ax, si
	out dx, ax
	ret
