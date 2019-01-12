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
