#
# Bareflank Hypervisor
#
# Copyright (C) 2015 Assured Information Security, Inc.
# Author: Rian Quinn        <quinnr@ainfosec.com>
# Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA


.text
.align
.global _vmcall
_vmcall:

    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    movq 0x00(%rdi),%rax
    movq 0x08(%rdi),%rdx
    movq 0x10(%rdi),%rcx
    movq 0x18(%rdi),%rbx
    movq 0x20(%rdi),%rsi
    movq 0x28(%rdi),%r8
    movq 0x30(%rdi),%r9
    movq 0x38(%rdi),%r10
    movq 0x40(%rdi),%r11
    movq 0x48(%rdi),%r12
    movq 0x50(%rdi),%r13
    movq 0x58(%rdi),%r14
    movq 0x60(%rdi),%r15

    vmcall

    movq %r15,0x60(%rdi)
    movq %r14,0x58(%rdi)
    movq %r13,0x50(%rdi)
    movq %r12,0x48(%rdi)
    movq %r11,0x40(%rdi)
    movq %r10,0x38(%rdi)
    movq %r9,0x30(%rdi)
    movq %r8,0x28(%rdi)
    movq %rsi,0x20(%rdi)
    movq %rbx,0x18(%rdi)
    movq %rcx,0x10(%rdi)
    movq %rdx,0x08(%rdi)
    movq %rax,0x00(%rdi)

    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx

    ret
