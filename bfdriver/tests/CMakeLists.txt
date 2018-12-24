#
# Copyright (C) 2019 Assured Information Security, Inc.
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

#do_test(test_common_add_module DEPENDS test_support)
#do_test(test_common_dump DEPENDS test_support)
#do_test(test_common_fini DEPENDS test_support)
#do_test(test_common_init DEPENDS test_support)
#do_test(test_common_load DEPENDS test_support)
#do_test(test_common_start DEPENDS test_support)
#do_test(test_common_stop DEPENDS test_support)
#do_test(test_common_unload DEPENDS test_support)
