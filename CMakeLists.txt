#
# Copyright (C) 2020 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

cmake_minimum_required(VERSION 3.13)
project(hypervisor C CXX ASM)

include(${CMAKE_CURRENT_LIST_DIR}/cmake/init_build.cmake)

if(NOT CMAKE_BUILD_TYPE STREQUAL CODECOV)
    if(HYPERVISOR_BUILD_LOADER)
        add_subdirectory(loader)
    endif()

    if(HYPERVISOR_BUILD_VMMCTL)
        add_subdirectory(vmmctl)
    endif()

    if(HYPERVISOR_BUILD_MICROKERNEL)
        hypervisor_add_mk_cross_compile(cmake/mk_cross_compile)
    endif()

    hypervisor_add_ext_cross_compile(cmake/ext_cross_compile)

    if(BUILD_TESTS AND NOT HYPERVISOR_BUILD_TESTS_OVERRIDE)
        include(kernel/integration/CMakeLists_Targets.cmake)
    endif()
endif()

if(NOT CMAKE_BUILD_TYPE STREQUAL RELEASE AND NOT CMAKE_BUILD_TYPE STREQUAL MINSIZEREL)
    if(BUILD_TESTS AND NOT HYPERVISOR_BUILD_TESTS_OVERRIDE)
        add_subdirectory(example/default/test)
        add_subdirectory(kernel/test)
        # add_subdirectory(loader/test)
        add_subdirectory(runtime/test)
        add_subdirectory(syscall/test)
        add_subdirectory(vmmctl/test)
    endif()
endif()
