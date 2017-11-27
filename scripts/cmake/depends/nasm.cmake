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

find_program(NASM_BIN nasm)
set(NASM_BIN ${NASM_BIN} CACHE INTERNAL "")
execute_process(COMMAND ${NASM_BIN} -v OUTPUT_VARIABLE NASM_ID OUTPUT_STRIP_TRAILING_WHITESPACE)
set(CMAKE_ASM_NASM_COMPILER_ID ${NASM_ID})
if(CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_ASM_NASM_OBJECT_FORMAT "elf64")
endif()
enable_language(ASM_NASM)
