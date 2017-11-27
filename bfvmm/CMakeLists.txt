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

cmake_minimum_required(VERSION 3.6)
project(bfvmm C CXX)
include(${BF_FLAGS_DIR}/flags.cmake)

# set(CMAKE_ASM_NASM_OBJECT_FORMAT "elf64")
enable_language(ASM_NASM)

list(APPEND VMM_C_FLAGS
    "-fvisibility=hidden"
)

list(APPEND VMM_CXX_FLAGS
    "-fvisibility=hidden"
    "-fvisibility-inlines-hidden"
)

generate_flags(
    VMM
    ADD_C_FLAGS ${VMM_C_FLAGS}
    ADD_CXX_FLAGS ${VMM_CXX_FLAGS}
    VERBOSE ${BUILD_VERBOSE}
)

include_directories(
    ${CMAKE_CURRENT_LIST_DIR}/include
    ${BUILD_SYSROOT_VMM}/include/c++/v1
    ${BUILD_SYSROOT_VMM}/include
)

link_directories(
    ${BUILD_SYSROOT_VMM}/lib
)

add_subdirectory(src)

install(DIRECTORY include/ DESTINATION ${BUILD_SYSROOT_VMM}/include)
