#
# Bareflank Hypervisor
#
# Copyright (C) 2015 Assured Information Security, Inc.
# Author: Bradley Hensel        <henselb@ainfosec.com>
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
