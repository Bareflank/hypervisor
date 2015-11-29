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

global exec_ms64tosv64

section .text
exec_ms64tosv64:

    ; Microsoft ABI
    ;   - RCX: First argument (entry point)
    ;   - RDX: Second argument (argument to be given to the entry point)
    ;   - RAX: Return register

    ; System V ABI
    ;   - RDI: First argument (argument to be given to the entry point)
    ;   - RAX: Return register

    ; Save off the nonvolatile registers as defined by the following:
    ; https://msdn.microsoft.com/en-us/library/6t169e9c.aspx
    push rbx
    push rbp
    push rdi
    push rsi
    push rsp
    push r12
    push r13
    push r14
    push r15

    mov     rdi, rdx
    call    rcx

    ; Restore the nonvolatile registers
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsp
    pop rsi
    pop rdi
    pop rbp
    pop rbx

    ret
