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

global __read_cr0:function
__read_cr0:
    mov rax, cr0
    ret

global __write_cr0:function
__write_cr0:
    mov cr0, rdi
    ret

global __read_cr2:function
__read_cr2:
    mov rax, cr2
    ret

global __write_cr2:function
__write_cr2:
    mov cr2, rdi
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
