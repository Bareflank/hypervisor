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

    serial_write_c PROTO

    serial_write_hex_text SEGMENT ALIGN(1000h) 'CODE'
    serial_write_hex PROC
    push rdx

    mov rdx, rcx

    mov rcx, 30h
    call serial_write_c

    mov rcx, 78h
    call serial_write_c

    mov rcx, rdx
    shr rcx, 60
    and rcx, 0FFh
    call serial_write_hex_digit

    mov rcx, rdx
    shr rcx, 56
    and rcx, 0FFh
    call serial_write_hex_digit

    mov rcx, rdx
    shr rcx, 52
    and rcx, 0FFh
    call serial_write_hex_digit

    mov rcx, rdx
    shr rcx, 48
    and rcx, 0FFh
    call serial_write_hex_digit

    mov rcx, rdx
    shr rcx, 44
    and rcx, 0FFh
    call serial_write_hex_digit

    mov rcx, rdx
    shr rcx, 40
    and rcx, 0FFh
    call serial_write_hex_digit

    mov rcx, rdx
    shr rcx, 36
    and rcx, 0FFh
    call serial_write_hex_digit

    mov rcx, rdx
    shr rcx, 32
    and rcx, 0FFh
    call serial_write_hex_digit

    mov rcx, rdx
    shr rcx, 28
    and rcx, 0FFh
    call serial_write_hex_digit

    mov rcx, rdx
    shr rcx, 24
    and rcx, 0FFh
    call serial_write_hex_digit

    mov rcx, rdx
    shr rcx, 20
    and rcx, 0FFh
    call serial_write_hex_digit

    mov rcx, rdx
    shr rcx, 16
    and rcx, 0FFh
    call serial_write_hex_digit

    mov rcx, rdx
    shr rcx, 12
    and rcx, 0FFh
    call serial_write_hex_digit

    mov rcx, rdx
    shr rcx, 8
    and rcx, 0FFh
    call serial_write_hex_digit

    mov rcx, rdx
    shr rcx, 4
    and rcx, 0FFh
    call serial_write_hex_digit

    mov rcx, rdx
    and rcx, 0FFh
    call serial_write_hex_digit

    pop rdx
    ret
    int 3

serial_write_hex_digit:

    cmp rcx, 9
    jg  serial_write_hex_digit_a_to_f

    add rcx, 30h
    call serial_write_c

    ret
    int 3

serial_write_hex_digit_a_to_f:

    add rcx, 37h
    call serial_write_c

    ret
    int 3

    serial_write_hex ENDP
    serial_write_hex_text ENDS
    end
