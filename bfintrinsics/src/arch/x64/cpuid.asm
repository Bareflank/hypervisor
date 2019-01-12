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
