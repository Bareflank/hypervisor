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

# TODO: This toolchain uses the legacy "compiler_wrapper.sh" script, along
# with a version of binutils built from source to emulate
# a new clang compiler and binutils for bare-metal x86_64 targets.
# This toolchain works, but is extremely complex. It would be preferable to
# replace this toolchain with clang_x86_64_none_elf.cmake in the future

set(CMAKE_SYSTEM_NAME Linux)

# Hack to allow toolchain files to access cmake cache variables
if(BUILD_SYSROOT_VMM)
    set(ENV{_BUILD_SYSROOT_VMM} "${BUILD_SYSROOT_VMM}")
else()
    set(BUILD_SYSROOT_VMM "$ENV{_BUILD_SYSROOT_VMM}")
endif()

# C and C++ compiler
find_program(CC_PATH x86_64-vmm-clang "${BUILD_SYSROOT_VMM}/bin")
set(CMAKE_C_COMPILER ${CC_PATH} CACHE INTERNAL "")
set(CMAKE_CXX_COMPILER ${CC_PATH} CACHE INTERNAL "")

# Assembler and other binutils
find_program(NASM_PATH nasm)
set(CMAKE_ASM_COMPILER ${NASM_PATH} CACHE INTERNAL "")
find_program(AR_PATH x86_64-vmm-elf-ar "${BUILD_SYSROOT_VMM}/bin")
set(CMAKE_AR ${AR_PATH} CACHE INTERNAL "")
find_program(RANLIB_PATH x86_64-vmm-elf-ranlib "${BUILD_SYSROOT_VMM}/bin")
set(CMAKE_RANLIB ${RANLIB_PATH} CACHE INTERNAL "")
find_program(OBJCOPY_PATH x86_64-vmm-elf-objcopy "${BUILD_SYSROOT_VMM}/bin")
set(CMAKE_OBJCOPY ${OBJCOPY_PATH} CACHE INTERNAL "")
