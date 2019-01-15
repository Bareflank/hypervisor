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

unset(BFFLAGS_EFI)
unset(BFFLAGS_EFI_C)
unset(BFFLAGS_EFI_CXX)
unset(BFFLAGS_EFI_X86_64)
unset(BFFLAGS_EFI_AARCH64)

list(APPEND BFFLAGS_EFI
    -isystem ${EFI_PREFIX_PATH}/include/efi/
    -isystem ${EFI_PREFIX_PATH}/include/efi/x86_64/
)

list(APPEND BFFLAGS_EFI
    -mno-red-zone
    -mno-avx
    # -maccumulate-outgoing-args
    -g
    -O2
    -Wall
    -Wextra
    -Wno-error=pragmas
    -fshort-wchar
    -fno-strict-aliasing
    -ffreestanding
    -fno-stack-protector
    -fno-stack-check
    -fno-merge-all-constants
    -DCONFIG_x86_64
    -DGNU_EFI_USE_MS_ABI
    -D__KERNEL__
    -DKERNEL
    -DEFI
)

list(APPEND BFFLAGS_EFI_C
    --std=c11
)

list(APPEND BFFLAGS_EFI_CXX
)

list(APPEND BFFLAGS_EFI_X86_64
)
