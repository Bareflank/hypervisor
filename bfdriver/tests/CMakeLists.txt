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

include(${SOURCE_CMAKE_DIR}/project.cmake)
init_project(
    INCLUDES ../include
    CXX_FLAGS -DVMM_PREFIX_PATH='"${VMM_PREFIX_PATH}"'
)

list(APPEND SOURCES
    test_support.cpp
    ${SOURCE_BFDRIVER_DIR}/src/common.c
    ${SOURCE_BFDRIVER_DIR}/src/platform/test/platform.c
)

add_static_library(
    test_support
    SOURCES ${SOURCES}
    ALWAYS
)

do_test(test_common_add_module DEPENDS test_support)
do_test(test_common_dump DEPENDS test_support)
do_test(test_common_fini DEPENDS test_support)
do_test(test_common_init DEPENDS test_support)
do_test(test_common_load DEPENDS test_support)
do_test(test_common_start DEPENDS test_support)
do_test(test_common_stop DEPENDS test_support)
do_test(test_common_unload DEPENDS test_support)
