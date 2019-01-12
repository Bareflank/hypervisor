;
; Bareflank Hypervisor
; Copyright (C) 2015 Assured Information Security, Inc.
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

global _cpuid_eax
_cpuid_eax:
    push rbx
    push rdi

%ifdef MS64
    mov rdi, rcx
%endif

    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    xor rdx, rdx

    mov eax, edi
    cpuid

    pop rdi
    pop rbx
    ret

global _cpuid_ebx
_cpuid_ebx:
    push rbx
    push rdi

%ifdef MS64
    mov rdi, rcx
%endif

    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    xor rdx, rdx

    mov eax, edi
    cpuid
    mov eax, ebx

    pop rdi
    pop rbx
    ret

global _cpuid_ecx
_cpuid_ecx:
    push rbx
    push rdi

%ifdef MS64
    mov rdi, rcx
%endif

    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    xor rdx, rdx

    mov eax, edi
    cpuid
    mov eax, ecx

    pop rdi
    pop rbx
    ret

global _cpuid_edx
_cpuid_edx:
    push rbx
    push rdi

%ifdef MS64
    mov rdi, rcx
%endif

    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    xor rdx, rdx

    mov eax, edi
    cpuid
    mov eax, edx

    pop rdi
    pop rbx
    ret

global _cpuid_subeax
_cpuid_subeax:
    push rbx
    push rdi
    push rsi

%ifdef MS64
    mov rdi, rcx
    mov rsi, rdx
%endif

    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    xor rdx, rdx

    mov eax, edi
    mov ecx, esi
    cpuid

    pop rsi
    pop rdi
    pop rbx
    ret

global _cpuid_subebx
_cpuid_subebx:
    push rbx
    push rdi
    push rsi

%ifdef MS64
    mov rdi, rcx
    mov rsi, rdx
%endif

    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    xor rdx, rdx

    mov eax, edi
    mov ecx, esi
    cpuid
    mov eax, ebx

    pop rsi
    pop rdi
    pop rbx
    ret

global _cpuid_subecx
_cpuid_subecx:
    push rbx
    push rdi
    push rsi

%ifdef MS64
    mov rdi, rcx
    mov rsi, rdx
%endif

    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    xor rdx, rdx

    mov eax, edi
    mov ecx, esi
    cpuid
    mov eax, ecx

    pop rsi
    pop rdi
    pop rbx
    ret

global _cpuid_subedx
_cpuid_subedx:
    push rbx
    push rdi
    push rsi

%ifdef MS64
    mov rdi, rcx
    mov rsi, rdx
%endif

    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    xor rdx, rdx

    mov eax, edi
    mov ecx, esi
    cpuid
    mov eax, edx

    pop rsi
    pop rdi
    pop rbx
    ret

global _cpuid
_cpuid:
    push rbx

%ifdef MS64
    mov r10, r8
    mov r11, r9
    mov r8, rcx
    mov r9, rdx
%else
    mov r10, rdx
    mov r11, rcx
    mov r8, rdi
    mov r9, rsi
%endif

    mov eax, [r8]
    mov ebx, [r9]
    mov ecx, [r10]
    mov edx, [r11]

    cpuid

    mov [r8], eax
    mov [r9], ebx
    mov [r10], ecx
    mov [r11], edx

    mov rax, 0

    pop rbx
    ret
