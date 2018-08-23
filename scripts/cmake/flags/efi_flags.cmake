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
    -fpic
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
