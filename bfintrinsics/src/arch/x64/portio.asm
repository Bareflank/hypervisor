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

global _inb
_inb:
    xor rax, rax
    mov rdx, rdi
    in al, dx
    ret

global _inw
_inw:
    xor rax, rax
    mov rdx, rdi
    in ax, dx
    ret

global _ind
_ind:
    xor rax, rax
    mov rdx, rdi
    in eax, dx
    ret

global _insb
_insb:
    mov rdx, rdi
    mov rdi, rsi
    insb
    xor rax, rax
    ret

global _insw
_insw:
    mov rdx, rdi
    mov rdi, rsi
    insw
    xor rax, rax
    ret

global _insd
_insd:
    mov rdx, rdi
    mov rdi, rsi
    insd
    xor rax, rax
    ret

global _insbrep
_insbrep:
    mov rcx, rdx
    mov rdx, rdi
    mov rdi, rsi
    cld
    rep insb
    xor rax, rax
    ret

global _inswrep
_inswrep:
    mov rcx, rdx
    mov rdx, rdi
    mov rdi, rsi
    cld
    rep insw
    xor rax, rax
    ret

global _insdrep
_insdrep:
    mov rcx, rdx
    mov rdx, rdi
    mov rdi, rsi
    cld
    rep insd
    xor rax, rax
    ret

global _outb
_outb:
    mov rdx, rdi
    mov rax, rsi
    out dx, al
    xor rax, rax
    ret

global _outw
_outw:
    mov rdx, rdi
    mov rax, rsi
    out dx, ax
    xor rax, rax
    ret

global _outd
_outd:
    mov rdx, rdi
    mov rax, rsi
    out dx, eax
    xor rax, rax
    ret

global _outsb
_outsb:
    mov rdx, rdi
    mov rdi, rsi
    outsb
    xor rax, rax
    ret

global _outsw
_outsw:
    mov rdx, rdi
    mov rdi, rsi
    outsw
    xor rax, rax
    ret

global _outsd
_outsd:
    mov rdx, rdi
    mov rdi, rsi
    outsd
    xor rax, rax
    ret

global _outsbrep
_outsbrep:
    mov rcx, rdx
    mov rdx, rdi
    mov rdi, rsi
    cld
    outsb
    xor rax, rax
    ret

global _outswrep
_outswrep:
    mov rcx, rdx
    mov rdx, rdi
    mov rdi, rsi
    cld
    outsw
    xor rax, rax
    ret

global _outsdrep
_outsdrep:
    mov rcx, rdx
    mov rdx, rdi
    mov rdi, rsi
    cld
    outsd
    xor rax, rax
    ret
