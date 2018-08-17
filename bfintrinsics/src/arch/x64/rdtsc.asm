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

; Note:
;
; To find more information about why RDTSC and RDTSCP are implemented this
; way, please see the following reference:
;
; http://www.intel.com/content/dam/www/public/us/en/documents/white-papers/ia-32-ia-64-benchmark-code-execution-paper.pdf
;
; Also it should be noted that this paper makes a critical mistake with
; RDTSC, complaining of variance. CPUID will introduce some variance, but it
; should not be as drastic as demonstrated in this paper as they forget to
; initialize at a minimum RAX prior to running CPUID which means that they are
; randomly accessing different leaf functions in CPUID introducing variance.
;

global _read_tsc
_read_tsc:

    push rbx

    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    xor rdx, rdx
    cpuid

    rdtsc
    shl rdx, 32
    or rax, rdx

    pop rbx
    ret

global _read_tscp
_read_tscp:

    push rbx

    rdtscp
    shl rdx, 32
    or rax, rdx

    mov rdi, rax

    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    xor rdx, rdx
    cpuid

    mov rax, rdi

    pop rbx
    ret
