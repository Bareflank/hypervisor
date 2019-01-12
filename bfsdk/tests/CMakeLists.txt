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
do_test(test_vcpuid)
do_test(test_vector)
