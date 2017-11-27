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
project(bfdriver_test C CXX)
include(${BF_FLAGS_DIR}/flags.cmake)
include(CTest)
enable_testing(true)

set(PROJECT_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/../src)
set(PROJECT_TEST_DIR ${CMAKE_CURRENT_LIST_DIR}/../tests)
set(PROJECT_INC_DIR ${CMAKE_CURRENT_LIST_DIR}/../include)

include_directories(
    "${PROJECT_INC_DIR}"
    "${PROJECT_TEST_DIR}"
    "${BUILD_SYSROOT_OS}/include"
    "${BUILD_SYSROOT_TEST}/include"
)

link_directories("${BUILD_SYSROOT_TEST}/lib")

list(APPEND BFDRIVER_CXX_FLAGS
    "-fno-stack-protector"
    "-DBAREFLANK_SYSROOT_PATH='\"${BUILD_SYSROOT_VMM}\"'"
)
generate_flags(
    USERSPACE
    ADD_CXX_FLAGS ${BFDRIVER_CXX_FLAGS}
    VERBOSE ${BUILD_VERBOSE}
)

add_library(bfdriver_test STATIC ${PROJECT_SRC_DIR}/common.c ${PROJECT_SRC_DIR}/arch/test/platform.c)
add_library(test_bfdriver_support STATIC test_support.cpp)

install(TARGETS bfdriver_test DESTINATION ${BUILD_SYSROOT_TEST}/lib)

macro(do_test str)
    add_executable(test_${str} test_${str}.cpp)
    target_link_libraries(test_${str} bfdriver_test)
    target_link_libraries(test_${str} test_bfdriver_support)
    target_link_libraries(test_${str} test_catch)
    add_test(bfelf_${str} test_${str})
    install(TARGETS test_${str} DESTINATION ${BUILD_SYSROOT_TEST}/bin/bfdriver)
endmacro(do_test)

do_test(common_add_module)
do_test(common_dump)
do_test(common_fini)
do_test(common_init)
do_test(common_load)
do_test(common_start)
do_test(common_stop)
do_test(common_unload)
