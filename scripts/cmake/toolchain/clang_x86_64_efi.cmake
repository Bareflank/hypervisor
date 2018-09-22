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

if(CMAKE_INSTALL_PREFIX)
    set(ENV{CMAKE_INSTALL_PREFIX} "${CMAKE_INSTALL_PREFIX}")
else()
    set(CMAKE_INSTALL_PREFIX "$ENV{CMAKE_INSTALL_PREFIX}")
endif()

set(CMAKE_SYSTEM_NAME Linux)

if(NOT WIN32)
    if(NOT DEFINED ENV{CLANG_BIN})
        find_program(CLANG_BIN clang)
    else()
        set(CLANG_BIN $ENV{CLANG_BIN})
    endif()

    if(CLANG_BIN)
        set(CMAKE_C_COMPILER ${CLANG_BIN})
        set(CMAKE_CXX_COMPILER ${CLANG_BIN})
    else()
        message(FATAL_ERROR "Unable to find clang")
    endif()
endif()

string(CONCAT LD_FLAGS_PRE
    "-nostdlib "
    "-shared "
    "-Bsymbolic "
    "-no-undefined "
    "-L ${CMAKE_INSTALL_PREFIX}/lib "
    "${CMAKE_INSTALL_PREFIX}/lib/crt0-efi-x86_64.o "
)

string(CONCAT LD_FLAGS_POST
    "-lefi "
    "-lgnuefi "
    "-T ${CMAKE_INSTALL_PREFIX}/lib/elf_x86_64_efi.lds "
)

set(CMAKE_C_CREATE_SHARED_LIBRARY
    "ld ${LD_FLAGS_PRE} <OBJECTS> ${LD_FLAGS_POST} -o <TARGET>"
)

set(CMAKE_CXX_CREATE_SHARED_LIBRARY
    "ld ${LD_FLAGS_PRE} <OBJECTS> ${LD_FLAGS_POST} -o <TARGET>"
)

set(CMAKE_C_COMPILER_WORKS 1)
set(CMAKE_CXX_COMPILER_WORKS 1)
