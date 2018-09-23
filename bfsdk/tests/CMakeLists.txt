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
project(bfsdk_test C CXX)

include(${SOURCE_CMAKE_DIR}/project.cmake)
init_project()

add_library(test_catch STATIC test_catch.cpp)
install(TARGETS test_catch DESTINATION lib)

do_test(test_affinity)
do_test(test_benchmark)
do_test(test_bitmanip)
do_test(test_buffer)
do_test(test_callonce)
do_test(test_debug)
do_test(test_debugringinterface)
do_test(test_delegate)
do_test(test_errorcodes)
do_test(test_exceptions)
do_test(test_file)
do_test(test_gsl)
do_test(test_json)
do_test(test_manager)
do_test(test_shuffle)
do_test(test_string)
do_test(test_types)
do_test(test_upperlower)
do_test(test_vector)
