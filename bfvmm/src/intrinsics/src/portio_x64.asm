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

global __inb:function
__inb:
    xor rax, rax
    mov rdx, rdi
    in al, dx
    ret

global __inw:function
__inw:
    xor rax, rax
    mov rdx, rdi
    in ax, dx
    ret

global __ind:function
__ind:
    xor rax, rax
    mov rdx, rdi
    in eax, dx
    ret

global __insb:function
__insb:
    mov rdx, rdi
    mov rdi, rsi
    insb
    xor rax, rax
    ret

global __insw:function
__insw:
    mov rdx, rdi
    mov rdi, rsi
    insw
    xor rax, rax
    ret

global __insd:function
__insd:
    mov rdx, rdi
    mov rdi, rsi
    insd
    xor rax, rax
    ret

global __insbrep:function
__insbrep:
    mov rcx, rdx
    mov rdx, rdi
    mov rdi, rsi
    rep insb
    xor rax, rax
    ret

global __inswrep:function
__inswrep:
    mov rcx, rdx
    mov rdx, rdi
    mov rdi, rsi
    rep insw
    xor rax, rax
    ret

global __insdrep:function
__insdrep:
    mov rcx, rdx
    mov rdx, rdi
    mov rdi, rsi
    rep insd
    xor rax, rax
    ret

global __outb:function
__outb:
    mov rdx, rdi
    mov rax, rsi
    out dx, al
    xor rax, rax
    ret

global __outw:function
__outw:
    mov rdx, rdi
    mov rax, rsi
    out dx, ax
    xor rax, rax
    ret

global __outd:function
__outd:
    mov rdx, rdi
    mov rax, rsi
    out dx, eax
    xor rax, rax
    ret

global __outbs:function
__outbs:
    mov rdx, rdi
    mov rdi, rsi
    outsb
    xor rax, rax
    ret

global __outws:function
__outws:
    mov rdx, rdi
    mov rdi, rsi
    outsw
    xor rax, rax
    ret

global __outds:function
__outds:
    mov rdx, rdi
    mov rdi, rsi
    outsd
    xor rax, rax
    ret

global __outbsrep:function
__outbsrep:
    mov rcx, rdx
    mov rdx, rdi
    mov rdi, rsi
    outsb
    xor rax, rax
    ret

global __outwsrep:function
__outwsrep:
    mov rcx, rdx
    mov rdx, rdi
    mov rdi, rsi
    outsw
    xor rax, rax
    ret

global __outdsrep:function
__outdsrep:
    mov rcx, rdx
    mov rdx, rdi
    mov rdi, rsi
    outsd
    xor rax, rax
    ret
