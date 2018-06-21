#
# Bareflank Hypervisor
# Copyright (C) 2015 Assured Information Security, Inc.
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

unset(BFFLAGS_VMM)
unset(BFFLAGS_VMM_C)
unset(BFFLAGS_VMM_CXX)
unset(BFFLAGS_VMM_X86_64)
unset(BFFLAGS_VMM_AARCH64)

list(APPEND BFFLAGS_VMM
    -isystem ${VMM_PREFIX_PATH}/include/c++/v1
    -isystem ${VMM_PREFIX_PATH}/include
)

list(APPEND BFFLAGS_VMM
    --target=${BUILD_TARGET_ARCH}-vmm-elf
    --sysroot=${VMM_PREFIX_PATH}
    -fpic
    -mno-red-zone
    -mstackrealign
    -fstack-protector-strong
    -DVMM
    -D${OSTYPE}
    -D${ABITYPE}
    -DGSL_THROW_ON_CONTRACT_VIOLATION
    -DMALLOC_PROVIDED
    -DCLOCK_MONOTONIC
    -D_HAVE_LONG_DOUBLE
    -D_LDBL_EQ_DBL
    -D_POSIX_TIMERS
    -D_POSIX_THREADS
    -D_POSIX_PRIORITY_SCHEDULING
    -D_UNIX98_THREAD_MUTEX_ATTRIBUTES
    -U__STRICT_ANSI__
    -D__SINGLE_THREAD__
    -U__USER_LABEL_PREFIX__
    -D__USER_LABEL_PREFIX__=
    -D__ELF__
)

list(APPEND BFFLAGS_VMM_C
    -std=c11
)

list(APPEND BFFLAGS_VMM_CXX
    -x c++
    -std=c++17
)

list(APPEND BFFLAGS_VMM_X86_64
    -msse
    -msse2
    -msse3
)
