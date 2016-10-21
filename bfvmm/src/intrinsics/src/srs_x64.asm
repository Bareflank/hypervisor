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
