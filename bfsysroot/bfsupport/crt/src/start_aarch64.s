/*
 * Bareflank Hypervisor
 *
 * Copyright (C) 2017 Assured Information Security, Inc.
 * Author: Chris Pavlina     <pavlinac@ainfosec.com>
 * Author: Rian Quinn        <quinnr@ainfosec.com>
 * Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

.global _start
.section .text
.balign 4

// int64_t _start(uint64_t stack, crt_info_t *crt_info)
// x29 = fp, x30 = lr
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
