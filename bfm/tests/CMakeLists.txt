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

include(${SOURCE_CMAKE_DIR}/project.cmake)
init_project(
    INCLUDES ../include
)

add_static_library(
    test_support
    SOURCES ../src/main.cpp
    SOURCES ../src/command_line_parser.cpp
    SOURCES ../src/ioctl_driver.cpp
    ALWAYS
)

do_test(test_command_line_parser
    DEPENDS test_support
)

do_test(test_ioctl_driver
    DEPENDS test_support
)

do_test(test_main
    DEPENDS test_support
)
