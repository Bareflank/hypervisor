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

include(../cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

add_library(test_catch STATIC test.cpp)
add_dependencies(test_catch catch)

macro(do_test str)
    add_executable(test_${str} test_${str}.cpp)
    target_link_libraries(test_${str} test_catch)
    add_dependencies(test_${str} json)
    add_dependencies(test_${str} gsl)
    add_dependencies(test_${str} catch)
    add_dependencies(test_${str} hippomocks)
    add_test(test_${str} test_${str})
endmacro(do_test)

do_test(affinity)
do_test(benchmark)
do_test(bitmanip)
do_test(buffer)
do_test(debug)
do_test(debugringinterface)
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

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(TARGETS test_catch DESTINATION lib)
