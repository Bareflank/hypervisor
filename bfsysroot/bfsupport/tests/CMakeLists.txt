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
project(bfsupport_test C CXX)
include(CTest)
enable_testing(true)
include(${BF_FLAGS_DIR}/flags.cmake)

set(PROJECT_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/../)
set(PROJECT_TEST_DIR ${CMAKE_CURRENT_LIST_DIR}/../tests)
set(PROJECT_INC_DIR ${CMAKE_CURRENT_LIST_DIR}/../include)

include_directories(
    ${PROJECT_INC_DIR}
    ${BUILD_SYSROOT_OS}/include
    ${BUILD_SYSROOT_TEST}/include
)

link_directories(
    ${BUILD_SYSROOT_TEST}/lib
)

generate_flags(
    USERSPACE
    VERBOSE ${BUILD_VERBOSE}
)

add_library(bfcrt_userspace STATIC "${CMAKE_CURRENT_LIST_DIR}/../crt/src/crt.cpp")
target_compile_definitions(bfcrt_userspace PUBLIC STATIC_CRT)
target_compile_definitions(bfcrt_userspace PUBLIC ENABLE_UNITTESTING)
install(TARGETS bfcrt_userspace DESTINATION "${BUILD_SYSROOT_TEST}/lib")

add_subdirectory(${PROJECT_SRC_DIR}/crt/tests ${CMAKE_CURRENT_BINARY_DIR}/crt)
