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

global __vmxon:function
global __vmxoff:function

section .text

; uint64_t __vmxon(void *vmxon_region)
__vmxon:
    vmxon [rdi]
    jbe __vmx_failure
    jmp __vmx_success

; uint64_t __vmxoff(void)
__vmxoff:
    vmxoff
    jbe __vmx_failure
    jmp __vmx_success

; vmx instruction failed
__vmx_failure:
    mov rax, 0x1
    ret

; vmx instruction succeded
__vmx_success:
    mov rax, 0x1
    ret
