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

set(CMAKE_SYSTEM_NAME Generic CACHE INTERNAL "")
set(CMAKE_SYSTEM_PROCESSOR x86_64 CACHE INTERNAL "")
set(TOOLCHAIN_TRIPLE "x86_64-linux-gnu" CACHE INTERNAL "")
SET(CMAKE_CROSSCOMPILING ON CACHE INTERNAL "")

# C and C++ compiler
set(CMAKE_C_COMPILER "clang" CACHE INTERNAL "")
set(CMAKE_C_COMPILER_TARGET "x86_64-elf" CACHE INTERNAL "")
set(CMAKE_CXX_COMPILER "clang" CACHE INTERNAL "")
set(CMAKE_CXX_COMPILER_TARGET "x86_64-elf" CACHE INTERNAL "")

# Assembler and other binutils
set(CMAKE_ASM_COMPILER "${TOOLCHAIN_TRIPLE}-as" CACHE INTERNAL "")
set(CMAKE_AR "${TOOLCHAIN_TRIPLE}-ar" CACHE INTERNAL "")
set(CMAKE_RANLIB "${TOOLCHAIN_TRIPLE}-ranlib" CACHE INTERNAL "")
set(CMAKE_OBJCOPY "${TOOLCHAIN_TRIPLE}-objcopy" CACHE INTERNAL "")

# Linker
# Cmake doens't provide a CMAKE_LINKER option, so specify the linker like this:
set(CMAKE_C_LINK_EXECUTABLE
    "${TOOLCHAIN_TRIPLE}-ld \
    <CMAKE_C_LINK_FLAGS> <LINK_FLAGS> <OBJECTS> -o <TARGET> <LINK_LIBRARIES>"
    CACHE INTERNAL ""
)
set(CMAKE_CXX_LINK_EXECUTABLE
    "${TOOLCHAIN_TRIPLE}-ld \
    <CMAKE_CXX_LINK_FLAGS> <LINK_FLAGS> <OBJECTS> -o <TARGET> <LINK_LIBRARIES>"
    CACHE INTERNAL ""
)

# Disable cmake compiler and linker tests
# This allows aarch64-linux-gnu-ld to link for baremetal targets without
# having to pass the built-in cmake linker test (which fails for baremetal)
set(CMAKE_C_COMPILER_WORKS 1 CACHE INTERNAL "")
set(CMAKE_CXX_COMPILER_WORKS 1 CACHE INTERNAL "")
