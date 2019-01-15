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

; Note:
;
; To find more information about why RDTSC and RDTSCP are implemented this
; way, please see the following reference:
;
; http://www.intel.com/content/dam/www/public/us/en/documents/white-papers/ia-32-ia-64-benchmark-code-execution-paper.pdf
;
; Also it should be noted that this paper makes a critical mistake with
; RDTSC, complaining of variance. CPUID will introduce some variance, but it
; should not be as drastic as demonstrated in this paper as they forget to
; initialize at a minimum RAX prior to running CPUID which means that they are
; randomly accessing different leaf functions in CPUID introducing variance.
;

global _read_tsc
_read_tsc:

    push rbx

    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    xor rdx, rdx
    cpuid

    rdtsc
    shl rdx, 32
    or rax, rdx

    pop rbx
    ret

global _read_tscp
_read_tscp:

    push rbx

    rdtscp
    shl rdx, 32
    or rax, rdx

    mov rdi, rax

    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    xor rdx, rdx
    cpuid

    mov rax, rdi

    pop rbx
    ret
