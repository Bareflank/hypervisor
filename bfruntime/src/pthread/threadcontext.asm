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

; For more information about how these functions work, please see the
; following reference:
;
; https://github.com/Bareflank/hypervisor/issues/213
;
; Note: If the constants.h file changes, or the thread_context structure
;       changes, this code might also have to change as well.

global _thread_context_tlsptr:function
_thread_context_tlsptr:

    mov rdx, 0x8000
    sub rdx, 0x1

    mov rax, rsp
    mov rcx, rdx
    not rcx
    and rax, rcx

    add rax, rdx

    sub rax, 24

    mov rax, [rax]
    ret

global _thread_context_cpuid:function
_thread_context_cpuid:

    mov rdx, 0x8000
    sub rdx, 0x1

    mov rax, rsp
    mov rcx, rdx
    not rcx
    and rax, rcx

    add rax, rdx

    sub rax, 32

    mov rax, [rax]
    ret
