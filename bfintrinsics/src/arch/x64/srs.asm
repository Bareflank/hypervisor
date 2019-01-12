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

global _read_es
_read_es:
    xor rax, rax
    mov ax, es
    ret

global _write_es
_write_es:
    xor rax, rax
    mov es, di
    ret

global _read_cs
_read_cs:
    xor rax, rax
    mov ax, cs
    ret

global _write_cs
_write_cs:

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

global _read_ss
_read_ss:
    xor rax, rax
    mov ax, ss
    ret

global _write_ss
_write_ss:
    mov ss, di
    ret

global _read_ds
_read_ds:
    xor rax, rax
    mov ax, ds
    ret

global _write_ds
_write_ds:
    mov ds, di
    ret

global _read_fs
_read_fs:
    xor rax, rax
    mov ax, fs
    ret

global _write_fs
_write_fs:
    mov fs, di
    ret

global _read_gs
_read_gs:
    xor rax, rax
    mov ax, gs
    ret

global _write_gs
_write_gs:
    mov gs, di
    ret

global _read_ldtr
_read_ldtr:
    xor rax, rax
    sldt ax
    ret

global _write_ldtr
_write_ldtr:
    lldt di
    ret

global _read_tr
_read_tr:
    xor rax, rax
    str ax
    ret

global _write_tr
_write_tr:
    ltr di
    ret
