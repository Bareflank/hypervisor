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
project(bfunwind C CXX)
include(${BF_FLAGS_DIR}/flags.cmake)

set(CMAKE_ASM_NASM_OBJECT_FORMAT "elf64")
enable_language(ASM_NASM)

if(ENABLE_UNITTESTING)
    include(CTest)
    enable_testing(true)
endif()

set(TIDY_EXCLUSIONS ,-cppcoreguidelines-pro*)

include_directories(${BUILD_SYSROOT_VMM}/include)
include_directories(${BF_SOURCE_DIR}/bfsdk/include)
include_directories(${CMAKE_CURRENT_LIST_DIR}/include)

generate_flags(
    VMM
    VERBOSE ${BUILD_VERBOSE}
)

add_subdirectory(src)

install(FILES include/ia64_cxx_abi.h DESTINATION ${BUILD_SYSROOT_VMM}/include RENAME unwind.h)
