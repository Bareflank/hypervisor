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

    .text

	.global serial_write_hex
    .type   serial_write_hex, @function
serial_write_hex:
    stp x29, x30, [sp, #-0x10]!
    stp x19, x20, [sp, #-0x10]!
    stp x0, x1, [sp, #-0x10]!

    mov x19, x0
    mov x20, #0xF

    mov x0, #0x30
    bl serial_write_c

    mov x0, #0x78
    bl serial_write_c

    and x0, x20, x19, LSR #60
    bl serial_write_hex_digit

    and x0, x20, x19, LSR #56
    bl serial_write_hex_digit

    and x0, x20, x19, LSR #52
    bl serial_write_hex_digit

    and x0, x20, x19, LSR #48
    bl serial_write_hex_digit

    and x0, x20, x19, LSR #44
    bl serial_write_hex_digit

    and x0, x20, x19, LSR #40
    bl serial_write_hex_digit

    and x0, x20, x19, LSR #36
    bl serial_write_hex_digit

    and x0, x20, x19, LSR #32
    bl serial_write_hex_digit

    and x0, x20, x19, LSR #28
    bl serial_write_hex_digit

    and x0, x20, x19, LSR #24
    bl serial_write_hex_digit

    and x0, x20, x19, LSR #20
    bl serial_write_hex_digit

    and x0, x20, x19, LSR #16
    bl serial_write_hex_digit

    and x0, x20, x19, LSR #12
    bl serial_write_hex_digit

    and x0, x20, x19, LSR #8
    bl serial_write_hex_digit

    and x0, x20, x19, LSR #4
    bl serial_write_hex_digit

    and x0, x20, x19
    bl serial_write_hex_digit

    ldp x0, x1, [sp], #0x10
    ldp x19, x20, [sp], #0x10
    ldp x29, x30, [sp], #0x10
    ret

serial_write_hex_digit:
    stp x29, x30, [sp, #-0x10]!

    cmp x0, #9
    bgt serial_write_hex_digit_a_to_f

    add x0, x0, #0x30
    bl serial_write_c

    ldp x29, x30, [sp], #0x10
    ret

serial_write_hex_digit_a_to_f:

    add x0, x0, #0x37
    bl serial_write_c

    ldp x29, x30, [sp], #0x10
    ret

    .size serial_write_hex, .-serial_write_hex
