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

	.global serial_write_c
    .type   serial_write_c, @function
serial_write_c:
    stp x0, x1, [sp, #-0x10]!

wait_for_ffio_empty:
    movz x1, #HYPERVISOR_SERIAL_PORTL
    movk x1, #HYPERVISOR_SERIAL_PORTH, LSL #16
    add  x1, x1, #0x18
    ldr  x1, [x1]

    and  x1, x1, #0x20
    cbnz x1, wait_for_ffio_empty

    movz x1, #HYPERVISOR_SERIAL_PORTL
    movk x1, #HYPERVISOR_SERIAL_PORTH, LSL #16
    str  x0, [x1]

    ldp x0, x1, [sp], #0x10
    ret
    

    .size serial_write_c, .-serial_write_c
