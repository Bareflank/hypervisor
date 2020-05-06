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

include(ExternalProject)

# Add Cross Compile Directory
#
# Uses ExternalProject_Add to add a subdirectory, but cross compiles instead
# instead of adding a subdirectory to the main project like add_subdirectory.
# This is needed to ensure the cross compiled code can have it's own toolchain.
#
# SOURCE_DIR: The location of the CMakeLists.txt that describes how to compile
#   the cross compiled components
#
function(hypervisor_add_cross_compile SOURCE_DIR)
    if(CMAKE_BUILD_TYPE STREQUAL ASAN OR
       CMAKE_BUILD_TYPE STREQUAL UBSAN)
        set(CMAKE_BUILD_TYPE DEBUG)
    endif()

    if(HYPERVISOR_TARGET_ARCH STREQUAL "x86_64")
        set(CMAKE_TOOLCHAIN_FILE ${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../toolchain/x86_64.cmake)
    elseif(HYPERVISOR_TARGET_ARCH STREQUAL "AMD64")
        set(CMAKE_TOOLCHAIN_FILE ${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../toolchain/amd64.cmake)
    else()
        message(FATAL_ERROR "Unsupported HYPERVISOR_TARGET_ARCH: ${HYPERVISOR_TARGET_ARCH}")
    endif()

    list(APPEND CMAKE_ARGS
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        -DCMAKE_VERBOSE_MAKEFILE=${CMAKE_VERBOSE_MAKEFILE}
        -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
        -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/cross_compile
        -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
        -DCMAKE_INSTALL_MESSAGE=LAZY
        -DFETCHCONTENT_UPDATES_DISCONNECTED=${FETCHCONTENT_UPDATES_DISCONNECTED}
    )

    list(APPEND CMAKE_ARGS
        -DBUILD_EXAMPLES=${BUILD_EXAMPLES}
        -DHYPERVISOR_BUILD_EXAMPLES_OVERRIDE=${HYPERVISOR_BUILD_EXAMPLES_OVERRIDE}
        -DHYPERVISOR_CXX_LINKER=${HYPERVISOR_CXX_LINKER}
    )

    ExternalProject_Add(
        cross_compile
        PREFIX          ${CMAKE_BINARY_DIR}/cross_compile
        STAMP_DIR       ${CMAKE_BINARY_DIR}/cross_compile/stamp
        TMP_DIR         ${CMAKE_BINARY_DIR}/cross_compile/tmp
        BINARY_DIR      ${CMAKE_BINARY_DIR}/cross_compile/build
        LOG_DIR         ${CMAKE_BINARY_DIR}/cross_compile/logs
        SOURCE_DIR      ${CMAKE_CURRENT_LIST_DIR}/${SOURCE_DIR}
        CMAKE_ARGS      ${CMAKE_ARGS}
        UPDATE_COMMAND  cmake -E echo -- Checking for changes
    )

    ExternalProject_Add_Step(
        cross_compile
        cross_compile_cleanup
        COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/cross_compile/src
        DEPENDEES configure
    )
endfunction(hypervisor_add_cross_compile)
