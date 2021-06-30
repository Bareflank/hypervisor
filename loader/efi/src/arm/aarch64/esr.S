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

	.global esr
	.align 12
esr:

    mov x19, x0
    mov x20, x1
    mov x21, x2
    mov x22, x3

    mov x0, #'\n'
    bl serial_write_c

    mov x0, #'\n'
    bl serial_write_c

    mov x0, #'\n'
    bl serial_write_c

    /**
     * NOTE:
     * - output: "exception:"
     */

    mov x0, #'e'
    bl serial_write_c

    mov x0, #'x'
    bl serial_write_c

    mov x0, #'c'
    bl serial_write_c

    mov x0, #'e'
    bl serial_write_c

    mov x0, #'p'
    bl serial_write_c

    mov x0, #'t'
    bl serial_write_c

    mov x0, #'i'
    bl serial_write_c

    mov x0, #'o'
    bl serial_write_c

    mov x0, #'n'
    bl serial_write_c

    mov x0, #':'
    bl serial_write_c

    mov x0, #'\n'
    bl serial_write_c

    /**
     * NOTE:
     * - output: " - vec: <vector #>"
     */

    mov x0, #' '
    bl serial_write_c

    mov x0, #'-'
    bl serial_write_c

    mov x0, #' '
    bl serial_write_c

    mov x0, #'v'
    bl serial_write_c

    mov x0, #'e'
    bl serial_write_c

    mov x0, #'c'
    bl serial_write_c

    mov x0, #':'
    bl serial_write_c

    mov x0, #' '
    bl serial_write_c

    mov x0, x19
    bl serial_write_hex

    mov x0, #'\n'
    bl serial_write_c

    /**
     * NOTE:
     * - output: " - esr: <esr_el2>"
     */

    mov x0, #' '
    bl serial_write_c

    mov x0, #'-'
    bl serial_write_c

    mov x0, #' '
    bl serial_write_c

    mov x0, #'e'
    bl serial_write_c

    mov x0, #'s'
    bl serial_write_c

    mov x0, #'r'
    bl serial_write_c

    mov x0, #':'
    bl serial_write_c

    mov x0, #' '
    bl serial_write_c

    mov x0, x20
    bl serial_write_hex

    mov x0, #'\n'
    bl serial_write_c

    /**
     * NOTE:
     * - output: " - far: <far_el2>"
     */

    mov x0, #' '
    bl serial_write_c

    mov x0, #'-'
    bl serial_write_c

    mov x0, #' '
    bl serial_write_c

    mov x0, #'f'
    bl serial_write_c

    mov x0, #'a'
    bl serial_write_c

    mov x0, #'r'
    bl serial_write_c

    mov x0, #':'
    bl serial_write_c

    mov x0, #' '
    bl serial_write_c

    mov x0, x21
    bl serial_write_hex

    mov x0, #'\n'
    bl serial_write_c

    /**
     * NOTE:
     * - output: " - spsr: <spsr_el2>"
     */

    mov x0, #' '
    bl serial_write_c

    mov x0, #'-'
    bl serial_write_c

    mov x0, #' '
    bl serial_write_c

    mov x0, #'s'
    bl serial_write_c

    mov x0, #'p'
    bl serial_write_c

    mov x0, #'s'
    bl serial_write_c

    mov x0, #'e'
    bl serial_write_c

    mov x0, #':'
    bl serial_write_c

    mov x0, #' '
    bl serial_write_c

    mov x0, x22
    bl serial_write_hex

    mov x0, #'\n'
    bl serial_write_c

loop_forever:
    b loop_forever
