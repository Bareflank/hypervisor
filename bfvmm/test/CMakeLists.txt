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
project(bfvmm_test C CXX)
include(${BF_FLAGS_DIR}/flags.cmake)
include(CTest)
enable_testing(true)

enable_language(ASM_NASM)

# Temp hacks until we can restructure unit tests
set(BUILD_VMM_STATIC ON)
set(BUILD_VMM_SHARED OFF)
set(BUILD_SYSROOT_VMM ${BUILD_SYSROOT_TEST})

list(APPEND VMM_TEST_C_FLAGS
    "-fvisibility=hidden"
    "-DDEBUG_LEVEL=1"
    "-DENABLE_UNITTESTING"
)

list(APPEND VMM_TEST_CXX_FLAGS
    "-fvisibility=hidden"
    "-fvisibility-inlines-hidden"
    "-DDEBUG_LEVEL=1"
    "-DENABLE_UNITTESTING"
)

generate_flags(
    USERSPACE
    ADD_C_FLAGS ${VMM_TEST_C_FLAGS}
    ADD_CXX_FLAGS ${VMM_TEST_CXX_FLAGS}
    VERBOSE ${BUILD_VERBOSE}
)

include_directories(
    ${CMAKE_CURRENT_LIST_DIR}/../include
    ${BUILD_SYSROOT_OS}/include
    ${BUILD_SYSROOT_TEST}/include
)

link_directories(
    ${BUILD_SYSROOT_OS}/lib
    ${BUILD_SYSROOT_TEST}/lib
)

add_subdirectory(../src ${CMAKE_CURRENT_BINARY_DIR}/src)
add_subdirectory(debug_ring)
add_subdirectory(exit_handler)
add_subdirectory(intrinsics)
add_subdirectory(memory_manager)
add_subdirectory(serial)
add_subdirectory(vcpu)
add_subdirectory(vcpu_factory)
add_subdirectory(vcpu_manager)
add_subdirectory(vmcs)
add_subdirectory(vmxon)

install(DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/../include/ DESTINATION ${BUILD_SYSROOT_VMM}/include)
