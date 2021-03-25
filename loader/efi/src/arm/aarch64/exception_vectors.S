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

	.global exception_vectors
	.align 12
exception_vectors:

    /* current el with sp_el0, synchronous */
    .align  7
    mov x0, #0x000
    mrs x1, esr_el2
    mrs x2, far_el2
    mrs x3, spsr_el2
    b   esr

    /* current el with sp_el0, irq or virq */
    .align  7
    mov x0, #0x080
    mov x1, xzr
    mov x2, xzr
    mrs x3, spsr_el2
    b   esr

    /* current el with sp_el0, fiq or vfiq */
    .align  7
    mov x0, #0x100
    mov x1, xzr
    mov x2, xzr
    mrs x3, spsr_el2
    b   esr

    /* current el with sp_el0, serror or vserror */
    .align  7
    mov x0, #0x180
    mov x1, xzr
    mov x2, xzr
    mrs x3, spsr_el2
    b   esr

    /* current el with sp_elx, synchronous */
    .align  7
    mov x0, #0x200
    mrs x1, esr_el2
    mrs x2, far_el2
    mrs x3, spsr_el2
    b   esr

    /* current el with sp_elx, irq or virq */
    .align  7
    mov x0, #0x280
    mov x1, xzr
    mov x2, xzr
    mrs x3, spsr_el2
    b   esr

    /* current el with sp_elx, fiq or vfiq */
    .align  7
    mov x0, #0x300
    mov x1, xzr
    mov x2, xzr
    mrs x3, spsr_el2
    b   esr

    /* current el with sp_elx, serror or vserror */
    .align  7
    mov x0, #0x380
    mov x1, xzr
    mov x2, xzr
    mrs x3, spsr_el2
    b   esr

    /* lower el from aarch64, synchronous */
    .align  7
    mov x0, #0x400
    mrs x1, esr_el2
    mrs x2, far_el2
    mrs x3, spsr_el2
    b   esr

    /* lower el from aarch64, irq or virq */
    .align  7
    mov x0, #0x480
    mov x1, xzr
    mov x2, xzr
    mrs x3, spsr_el2
    b   esr

    /* lower el from aarch64, fiq or vfiq */
    .align  7
    mov x0, #0x500
    mov x1, xzr
    mov x2, xzr
    mrs x3, spsr_el2
    b   esr

    /* lower el from aarch64, serror or vserror */
    .align  7
    mov x0, #0x580
    mov x1, xzr
    mov x2, xzr
    mrs x3, spsr_el2
    b   esr

    /* lower el from aarch32, synchronous */
    .align  7
    mov x0, #0x600
    mrs x1, esr_el2
    mrs x2, far_el2
    mrs x3, spsr_el2
    b   esr

    /* lower el from aarch32, irq or virq */
    .align  7
    mov x0, #0x680
    mov x1, xzr
    mov x2, xzr
    mrs x3, spsr_el2
    b   esr

    /* lower el from aarch32, fiq or vfiq */
    .align  7
    mov x0, #0x700
    mov x1, xzr
    mov x2, xzr
    mrs x3, spsr_el2
    b   esr

    /* lower el from aarch32, serror or vserror */
    .align  7
    mov x0, #0x780
    mov x1, xzr
    mov x2, xzr
    mrs x3, spsr_el2
    b   esr
