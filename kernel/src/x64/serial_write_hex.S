/**
 * @copyright
 * Copyright (C) 2020 Assured Information Security, Inc.
 *
 * @copyright
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * @copyright
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * @copyright
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

    .code64
    .intel_syntax noprefix

    .globl  serial_write_hex
    .type   serial_write_hex, @function
serial_write_hex:
    push rdx

    mov rdx, rdi

    mov rdi, 0x30
    call serial_write_c

    mov rdi, 0x78
    call serial_write_c

    mov rdi, rdx
    shr rdi, 60
    and rdi, 0xFF
    call serial_write_hex_digit

    mov rdi, rdx
    shr rdi, 56
    and rdi, 0xFF
    call serial_write_hex_digit

    mov rdi, rdx
    shr rdi, 52
    and rdi, 0xFF
    call serial_write_hex_digit

    mov rdi, rdx
    shr rdi, 48
    and rdi, 0xFF
    call serial_write_hex_digit

    mov rdi, rdx
    shr rdi, 44
    and rdi, 0xFF
    call serial_write_hex_digit

    mov rdi, rdx
    shr rdi, 40
    and rdi, 0xFF
    call serial_write_hex_digit

    mov rdi, rdx
    shr rdi, 36
    and rdi, 0xFF
    call serial_write_hex_digit

    mov rdi, rdx
    shr rdi, 32
    and rdi, 0xFF
    call serial_write_hex_digit

    mov rdi, rdx
    shr rdi, 28
    and rdi, 0xFF
    call serial_write_hex_digit

    mov rdi, rdx
    shr rdi, 24
    and rdi, 0xFF
    call serial_write_hex_digit

    mov rdi, rdx
    shr rdi, 20
    and rdi, 0xFF
    call serial_write_hex_digit

    mov rdi, rdx
    shr rdi, 16
    and rdi, 0xFF
    call serial_write_hex_digit

    mov rdi, rdx
    shr rdi, 12
    and rdi, 0xFF
    call serial_write_hex_digit

    mov rdi, rdx
    shr rdi, 8
    and rdi, 0xFF
    call serial_write_hex_digit

    mov rdi, rdx
    shr rdi, 4
    and rdi, 0xFF
    call serial_write_hex_digit

    mov rdi, rdx
    and rdi, 0xFF
    call serial_write_hex_digit

    pop rdx
    ret
    int 3

serial_write_hex_digit:

    cmp rdi, 9
    jg  serial_write_hex_digit_a_to_f

    add rdi, 0x30
    call serial_write_c

    ret
    int 3

serial_write_hex_digit_a_to_f:

    add rdi, 0x37
    call serial_write_c

    ret
    int 3

    .size serial_write_hex, .-serial_write_hex
