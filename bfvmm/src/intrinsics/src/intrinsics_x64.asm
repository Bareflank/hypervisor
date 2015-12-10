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

global __cpuid_eax:function
global __cpuid_ebx:function
global __cpuid_ecx:function
global __cpuid_edx:function
global __read_rflags:function
global __read_msr:function
global __write_msr:function
global __read_cr0:function
global __write_cr0:function
global __read_cr4:function
global __write_cr4:function

section .text

; uint32_t cpuid_eax(uint32_t val)
__cpuid_eax:
    push rbx
    push rcx
    push rdx

    mov eax, edi
    cpuid

    pop rdx
    pop rcx
    pop rbx
    ret

; uint32_t cpuid_ebx(uint32_t val)
__cpuid_ebx:
    push rbx
    push rcx
    push rdx

    mov eax, edi
    cpuid
    mov eax, ebx

    pop rdx
    pop rcx
    pop rbx
    ret

; uint32_t cpuid_ecx(uint32_t val)
__cpuid_ecx:
    push rbx
    push rcx
    push rdx

    mov eax, edi
    cpuid
    mov eax, ecx

    pop rdx
    pop rcx
    pop rbx
    ret

; uint32_t cpuid_edx(uint32_t val)
__cpuid_edx:
    push rbx
    push rcx
    push rdx

    mov eax, edi
    cpuid
    mov eax, edx

    pop rdx
    pop rcx
    pop rbx
    ret

; uint64_t read_rflags(void)
__read_rflags:
    pushfq
    pop rax
    ret

; uint64_t __read_msr(uint32_t msr)
__read_msr:
    push rcx
    push rdx

    mov ecx, edi
    rdmsr
    shl rdx, 32
    or rax, rdx

    pop rdx
    pop rcx
    ret

; void __write_msr(uint32_t msr, uint64_t val)
__write_msr:
    push rcx
    push rdx

    mov rax, rdi
    mov rdx, rdi
    shr rdx, 32
    wrmsr

    pop rdx
    pop rcx
    ret

; uint64_t __read_cr0()
__read_cr0:
    mov rax, cr0
    ret

; void __write_cr0(uint64_t val)
__write_cr0:
    mov cr0, rdi
    ret

; uint64_t __read_cr4()
__read_cr4:
    mov rax, cr4
    ret

; void __write_cr4(uint64_t val)
__write_cr4:
    mov cr4, rdi
    ret
