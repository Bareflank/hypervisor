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

cmake_minimum_required(VERSION 3.10)
project(bfsdk C CXX)

init_project(bfsdk INTERFACE)

# -----------------------------------------------------------------------------
# Common
# -----------------------------------------------------------------------------

target_link_libraries(bfsdk INTERFACE ${PREFIX}::bfroot)

if(NOT PREFIX STREQUAL test)
    install(DIRECTORY include/ DESTINATION include)
    fini_project()
    return()
endif()

# -----------------------------------------------------------------------------
# Test
# -----------------------------------------------------------------------------

target_link_libraries(bfsdk INTERFACE
    $<$<OR:$<BOOL:${CYGWIN}>,$<BOOL:${WIN32}>>:setupapi>
)
target_include_directories(bfsdk INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
)

do_test(tests/test_affinity.cpp)
do_test(tests/test_benchmark.cpp)
do_test(tests/test_bitmanip.cpp)
do_test(tests/test_buffer.cpp)
do_test(tests/test_callonce.cpp)
do_test(tests/test_debug.cpp)
do_test(tests/test_debugringinterface.cpp)
do_test(tests/test_delegate.cpp)
do_test(tests/test_errorcodes.cpp)
do_test(tests/test_exceptions.cpp)
do_test(tests/test_file.cpp)
do_test(tests/test_gsl.cpp)
do_test(tests/test_json.cpp)
do_test(tests/test_manager.cpp)
do_test(tests/test_shuffle.cpp)
do_test(tests/test_string.cpp)
do_test(tests/test_types.cpp)
do_test(tests/test_upperlower.cpp)
do_test(tests/test_vector.cpp)

#add_static_library(
#    test_support
#    SOURCES test_real_elf.cpp test_fake_elf.cpp
#    ALWAYS
#)
#
#do_test(test_binary DEPENDS test_support)
#do_test(test_file_get_entry DEPENDS test_support)
#do_test(test_file_get_load_instr DEPENDS test_support)
#do_test(test_file_get_needed DEPENDS test_support)
#do_test(test_file_get_num_load_instrs DEPENDS test_support)
#do_test(test_file_get_num_needed DEPENDS test_support)
#do_test(test_file_get_pic_pie DEPENDS test_support)
#do_test(test_file_get_section_info DEPENDS test_support)
#do_test(test_file_get_total_size DEPENDS test_support)
#do_test(test_file_init DEPENDS test_support)
#do_test(test_helpers DEPENDS test_support)
#do_test(test_load DEPENDS test_support)
#do_test(test_loader_add DEPENDS test_support)
#do_test(test_loader_relocate DEPENDS test_support)
#do_test(test_loader_resolve_symbol DEPENDS test_support)
#do_test(test_read_binary_and_get_needed_list DEPENDS test_support)
#do_test(test_real DEPENDS test_support)
#do_test(test_set_args DEPENDS test_support)
#do_test(test_set_integer_args DEPENDS test_support)

fini_project()
