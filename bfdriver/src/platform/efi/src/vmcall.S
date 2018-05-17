#
# Bareflank Hypervisor
# Copyright (C) 2018 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
#

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
