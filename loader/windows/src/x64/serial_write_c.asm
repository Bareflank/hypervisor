; @copyright
; Copyright (C) 2020 Assured Information Security, Inc.
;
; @copyright
; Permission is hereby granted, free of charge, to any person obtaining a copy
; of this software and associated documentation files (the "Software"), to deal
; in the Software without restriction, including without limitation the rights
; to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
; copies of the Software, and to permit persons to whom the Software is
; furnished to do so, subject to the following conditions:
;
; @copyright
; The above copyright notice and this permission notice shall be included in
; all copies or substantial portions of the Software.
;
; @copyright
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
; OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
; SOFTWARE.

include constants_masm.h

    serial_write_c_text SEGMENT ALIGN(1000h) 'CODE'
    serial_write_c PROC

    push rax
    push rdx

wait_for_ffio_empty:
    mov rdx, HYPERVISOR_SERIAL_PORT
    add rdx, 5
    in  al, dx

    and al, 20h
    cmp al, 0h
    jz  wait_for_ffio_empty

    mov rdx, HYPERVISOR_SERIAL_PORT
    mov rax, rcx
    out dx, al

    pop rdx
    pop rax
    ret
    int 3

    serial_write_c ENDP
    serial_write_c_text ENDS
    end
