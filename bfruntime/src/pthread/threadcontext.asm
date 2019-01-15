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

; For more information about how these functions work, please see the
; following reference:
;
; https://github.com/Bareflank/hypervisor/issues/213
;
; Note: If the constants.h file changes, or the thread_context structure
;       changes, this code might also have to change as well.

global _thread_context_tlsptr:function
_thread_context_tlsptr:

    mov rdx, 0x8000
    sub rdx, 0x1

    mov rax, rsp
    mov rcx, rdx
    not rcx
    and rax, rcx

    add rax, rdx

    sub rax, 24

    mov rax, [rax]
    ret

global _thread_context_cpuid:function
_thread_context_cpuid:

    mov rdx, 0x8000
    sub rdx, 0x1

    mov rax, rsp
    mov rcx, rdx
    not rcx
    and rax, rcx

    add rax, rdx

    sub rax, 32

    mov rax, [rax]
    ret
