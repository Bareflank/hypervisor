#
# Copyright (C) 2019 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

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
    -DSYSV
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

if(DEFINED ENABLE_BUILD_EFI)
    list(APPEND BFFLAGS_VMM
        -DENABLE_BUILD_EFI
    )
endif()
