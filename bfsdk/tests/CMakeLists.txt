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
project(bfm_test C CXX)
include(${BF_SCRIPTS_DIR}/cmake/flags/flags.cmake)
include(CTest)
enable_testing(true)
enable_language(ASM_NASM)

set(PROJECT_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/../src)
set(PROJECT_TEST_DIR ${CMAKE_CURRENT_LIST_DIR}/../tests)
set(PROJECT_INC_DIR ${CMAKE_CURRENT_LIST_DIR}/../include)

include_directories(
    ${PROJECT_INC_DIR}
    ${BUILD_SYSROOT_TEST}/include
    ${BUILD_SYSROOT_OS}/include
)

link_directories(
    ${BUILD_SYSROOT_TEST}/lib
)

add_library(test_catch STATIC test.cpp)
install(TARGETS test_catch DESTINATION ${BUILD_SYSROOT_TEST}/lib)

set(BFSDK_TEST_FLAGS "-DENABLE_UNITTESTING")
generate_flags(
    USERSPACE
    ADD_C_FLAGS ${BFSDK_TEST_FLAGS}
    ADD_CXX_FLAGS ${BFSDK_TEST_FLAGS}
    VERBOSE ${BUILD_VERBOSE}
)

macro(do_test str)
    add_executable(test_${str} test_${str}.cpp)
    target_link_libraries(test_${str} test_catch)
    add_test(test_${str} test_${str})
    install(TARGETS test_${str} DESTINATION ${BUILD_SYSROOT_TEST}/bin/bfsdk)
endmacro(do_test)

do_test(affinity)
do_test(benchmark)
do_test(bitmanip)
do_test(buffer)
do_test(debug)
do_test(debugringinterface)
do_test(delegate)
do_test(errorcodes)
do_test(exceptions)
do_test(file)
do_test(gsl)
do_test(json)
do_test(newdelete)
do_test(shuffle)
do_test(string)
do_test(types)
do_test(upperlower)
do_test(vector)

install(TARGETS test_catch DESTINATION ${BUILD_SYSROOT_TEST}/lib)
