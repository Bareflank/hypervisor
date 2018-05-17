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

.global _writerflags
_writerflags:

    pushq %rdi
    popfq

    ret


.global _readrflags
_readrflags:

    pushfq
    popq %rax

    ret


.global _sgdt
_sgdt:

    sgdt (%rdi)

    ret


.global _lgdt
_lgdt:

    lgdt (%rdi)

    ret


.global _ltr
_ltr:

    ltrw %di

    ret


.global _str
_str:

    strw %ax

    ret


.global _set_vmxe
_set_vmxe:

    movq %cr4, %rax
    orq $(1<<13), %rax
    movq %rax, %cr4

    ret

.global _unset_vmxe
_unset_vmxe:

    movq %cr4, %rax
    andq $~(1<<13), %rax
    movq %rax, %cr4

    ret

.global _set_ne
_set_ne:

    movq %cr0, %rax
    orq $(1<<5), %rax
    movq %rax, %cr0

    ret
