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

global _read_cr0
_read_cr0:
    mov rax, cr0
    ret

global _write_cr0
_write_cr0:
    mov cr0, rdi
    ret

global _read_cr2
_read_cr2:
    mov rax, cr2
    ret

global _write_cr2
_write_cr2:
    mov cr2, rdi
    ret

global _read_cr3
_read_cr3:
    mov rax, cr3
    ret

global _write_cr3
_write_cr3:
    mov cr3, rdi
    ret

global _read_cr4
_read_cr4:
    mov rax, cr4
    ret

global _write_cr4
_write_cr4:
    mov cr4, rdi
    ret

global _read_cr8
_read_cr8:
    mov rax, cr8
    ret

global _write_cr8
_write_cr8:
    mov cr8, rdi
    ret

global _write_xcr0
_write_xcr0:
    mov rax, rdi
    mov rdx, rdi
    shr rdx, 32
    mov rcx, 0
    xsetbv

    ret
