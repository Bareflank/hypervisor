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
project(bfelf_loader_test C CXX)

include(${SOURCE_CMAKE_DIR}/project.cmake)
init_project(
    CXX_FLAGS -DVMM_PREFIX_PATH='"${VMM_PREFIX_PATH}"'
)

add_static_library(
    test_support
    SOURCES test_real_elf.cpp test_fake_elf.cpp
    ALWAYS
)

do_test(test_binary DEPENDS test_support)
do_test(test_file_get_entry DEPENDS test_support)
do_test(test_file_get_load_instr DEPENDS test_support)
do_test(test_file_get_needed DEPENDS test_support)
do_test(test_file_get_num_load_instrs DEPENDS test_support)
do_test(test_file_get_num_needed DEPENDS test_support)
do_test(test_file_get_pic_pie DEPENDS test_support)
do_test(test_file_get_relro DEPENDS test_support)
do_test(test_file_get_section_info DEPENDS test_support)
do_test(test_file_get_stack_perm DEPENDS test_support)
do_test(test_file_get_total_size DEPENDS test_support)
do_test(test_file_init DEPENDS test_support)
do_test(test_helpers DEPENDS test_support)
do_test(test_load DEPENDS test_support)
do_test(test_loader_add DEPENDS test_support)
do_test(test_loader_relocate DEPENDS test_support)
do_test(test_loader_resolve_symbol DEPENDS test_support)
do_test(test_read_binary_and_get_needed_list DEPENDS test_support)
do_test(test_real DEPENDS test_support)
do_test(test_set_args DEPENDS test_support)
do_test(test_set_integer_args DEPENDS test_support)
