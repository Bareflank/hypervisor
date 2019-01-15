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

.global _start
.section .text
.balign 4

_start:
    stp  x29, x30, [sp, #-16]!
    mov  x29, sp

    mov  sp, x0
    mov  x0, x1

    adr  x1, canary
    ldr  x1, [x1]
    stp  x1, x1, [sp, #-16]!

    bl   _start_c

    adr  x1, canary
    ldr  x1, [x1]
    ldr  x2, [sp], #16

    mov  sp, x29

    cmp  x1, x2
    b.ne stack_overflow

    ldp  x29, x30, [sp], #16
    ret

stack_overflow:
    mov  x0, #0x0010
    movk x0, #0x8000, lsl #48       // x0 = 0x8000000000000010
    ldp  x29, x30, [sp], #16
    ret

canary:
    .word 0xABCDEF12, 0x34567890
