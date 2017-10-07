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

global _inb:function
_inb:
    xor rax, rax
    mov rdx, rdi
    in al, dx
    ret

global _inw:function
_inw:
    xor rax, rax
    mov rdx, rdi
    in ax, dx
    ret

global _ind:function
_ind:
    xor rax, rax
    mov rdx, rdi
    in eax, dx
    ret

global _insb:function
_insb:
    mov rdx, rdi
    mov rdi, rsi
    insb
    xor rax, rax
    ret

global _insw:function
_insw:
    mov rdx, rdi
    mov rdi, rsi
    insw
    xor rax, rax
    ret

global _insd:function
_insd:
    mov rdx, rdi
    mov rdi, rsi
    insd
    xor rax, rax
    ret

global _insbrep:function
_insbrep:
    mov rcx, rdx
    mov rdx, rdi
    mov rdi, rsi
    rep insb
    xor rax, rax
    ret

global _inswrep:function
_inswrep:
    mov rcx, rdx
    mov rdx, rdi
    mov rdi, rsi
    rep insw
    xor rax, rax
    ret

global _insdrep:function
_insdrep:
    mov rcx, rdx
    mov rdx, rdi
    mov rdi, rsi
    rep insd
    xor rax, rax
    ret

global _outb:function
_outb:
    mov rdx, rdi
    mov rax, rsi
    out dx, al
    xor rax, rax
    ret

global _outw:function
_outw:
    mov rdx, rdi
    mov rax, rsi
    out dx, ax
    xor rax, rax
    ret

global _outd:function
_outd:
    mov rdx, rdi
    mov rax, rsi
    out dx, eax
    xor rax, rax
    ret

global _outbs:function
_outbs:
    mov rdx, rdi
    mov rdi, rsi
    outsb
    xor rax, rax
    ret

global _outws:function
_outws:
    mov rdx, rdi
    mov rdi, rsi
    outsw
    xor rax, rax
    ret

global _outds:function
_outds:
    mov rdx, rdi
    mov rdi, rsi
    outsd
    xor rax, rax
    ret

global _outbsrep:function
_outbsrep:
    mov rcx, rdx
    mov rdx, rdi
    mov rdi, rsi
    outsb
    xor rax, rax
    ret

global _outwsrep:function
_outwsrep:
    mov rcx, rdx
    mov rdx, rdi
    mov rdi, rsi
    outsw
    xor rax, rax
    ret

global _outdsrep:function
_outdsrep:
    mov rcx, rdx
    mov rdx, rdi
    mov rdi, rsi
    outsd
    xor rax, rax
    ret
