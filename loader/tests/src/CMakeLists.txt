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

set(CURRENT_FUNCTION_LIST_DIR ${CMAKE_CURRENT_LIST_DIR})

# ------------------------------------------------------------------------------
# Sources Needed By All Tests
# ------------------------------------------------------------------------------

add_library(loader_tests_common)

target_include_directories(loader_tests_common PRIVATE
    ${COMMON_INCLUDES}
)

target_include_directories(loader_tests_common PRIVATE SYSTEM
    ${COMMON_SYSTEM_INCLUDES}
)

target_sources(loader_tests_common PRIVATE
    ${CURRENT_FUNCTION_LIST_DIR}/alloc_and_copy_mk_code_aliases.c
    ${CURRENT_FUNCTION_LIST_DIR}/alloc_and_copy_mk_state
    ${CURRENT_FUNCTION_LIST_DIR}/alloc_and_copy_root_vp_state
    ${CURRENT_FUNCTION_LIST_DIR}/alloc_mk_root_page_table.c
    ${CURRENT_FUNCTION_LIST_DIR}/check_cpu_configuration.c
    ${CURRENT_FUNCTION_LIST_DIR}/dump_mk_code_aliases.c
    ${CURRENT_FUNCTION_LIST_DIR}/dump_mk_root_page_table.c
    ${CURRENT_FUNCTION_LIST_DIR}/dump_mk_state.c
    ${CURRENT_FUNCTION_LIST_DIR}/dump_root_vp_state.c
    ${CURRENT_FUNCTION_LIST_DIR}/free_mk_code_aliases.c
    ${CURRENT_FUNCTION_LIST_DIR}/free_mk_root_page_table.c
    ${CURRENT_FUNCTION_LIST_DIR}/free_mk_state.c
    ${CURRENT_FUNCTION_LIST_DIR}/free_root_vp_state.c
    ${CURRENT_FUNCTION_LIST_DIR}/map_4k_page.c
    ${CURRENT_FUNCTION_LIST_DIR}/map_mk_code_aliases.c
    ${CURRENT_FUNCTION_LIST_DIR}/map_mk_state.c
    ${CURRENT_FUNCTION_LIST_DIR}/map_root_vp_state.c
    ${CURRENT_FUNCTION_LIST_DIR}/platform.c
    ${CURRENT_FUNCTION_LIST_DIR}/send_command_report_off.c
    ${CURRENT_FUNCTION_LIST_DIR}/send_command_report_on.c
    ${CURRENT_FUNCTION_LIST_DIR}/send_command_stop.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/g_mut_cpu_status.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/g_mut_ext_elf_files.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/g_mut_mk_args.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/g_mut_mk_code_aliases.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/g_mut_mk_elf_file.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/g_mut_mk_elf_segments.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/g_mut_mk_huge_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/g_mut_mk_huge_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/g_mut_mk_page_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/g_pmut_mut_mk_root_page_table.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/g_mut_mk_stack.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/g_mut_mk_state.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/g_pmut_mut_mk_debug_ring.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/g_mut_root_vp_state.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/g_mut_vmm_status.c
)

target_compile_definitions(loader_tests_common PRIVATE
    ${COMMON_DEFINES}
)

# ------------------------------------------------------------------------------
# Macros For This Directory
# ------------------------------------------------------------------------------

macro(loader_add_test NAME)
    bf_add_test(
        test_${NAME}
        SOURCES ${ARGN}
        INCLUDES ${COMMON_INCLUDES}
        SYSTEM_INCLUDES ${COMMON_SYSTEM_INCLUDES}
        DEFINES ${COMMON_DEFINES}
        DEFINES DEBUG_LOADER
        LIBRARIES loader_tests_common
    )
endmacro(loader_add_test)

# ------------------------------------------------------------------------------
# Mocks
# ------------------------------------------------------------------------------

loader_add_test(helpers)
loader_add_test(platform)

# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------

loader_add_test(alloc_and_copy_ext_elf_files_from_user
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_and_copy_ext_elf_files_from_user.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_ext_elf_files.c)

loader_add_test(alloc_and_copy_mk_elf_file_from_user
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_and_copy_mk_elf_file_from_user.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_elf_file.c)

loader_add_test(alloc_and_copy_mk_elf_segments
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_and_copy_mk_elf_segments.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_elf_segments.c)

loader_add_test(alloc_mk_args
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_args.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_args.c)

loader_add_test(alloc_mk_debug_ring
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_debug_ring.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_debug_ring.c)

loader_add_test(alloc_mk_huge_pool
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_huge_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_huge_pool.c)

loader_add_test(alloc_mk_page_pool
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_page_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_page_pool.c)

loader_add_test(alloc_mk_stack
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_stack.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_stack.c)

loader_add_test(dump_ext_elf_files ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_ext_elf_files.c)
loader_add_test(dump_mk_args ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_args.c)
loader_add_test(dump_mk_debug_ring ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_debug_ring.c)
loader_add_test(dump_mk_elf_file ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_elf_file.c)
loader_add_test(dump_mk_elf_segments ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_elf_segments.c)
loader_add_test(dump_mk_huge_pool ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_huge_pool.c)
loader_add_test(dump_mk_page_pool ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_page_pool.c)
loader_add_test(dump_mk_root_page_table ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_root_page_table.c)
loader_add_test(dump_mk_stack ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_stack.c)

loader_add_test(dump_vmm
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_vmm.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/loader_init.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/loader_fini.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_debug_ring.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_debug_ring.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_ext_elf_files.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_args.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_debug_ring.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_elf_file.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_elf_segments.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_huge_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_page_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_stack.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/stop_vmm_per_cpu.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/stop_and_free_the_vmm.c)

loader_add_test(free_ext_elf_files
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_and_copy_ext_elf_files_from_user.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_ext_elf_files.c)

loader_add_test(free_mk_elf_file
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_and_copy_mk_elf_file_from_user.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_elf_file.c)

loader_add_test(free_mk_elf_segments
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_and_copy_mk_elf_segments.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_elf_segments.c)

loader_add_test(free_mk_args
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_args.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_args.c)

loader_add_test(free_mk_debug_ring
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_debug_ring.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_debug_ring.c)

loader_add_test(free_mk_huge_pool
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_huge_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_huge_pool.c)

loader_add_test(free_mk_page_pool
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_page_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_page_pool.c)

loader_add_test(free_mk_stack
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_stack.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_stack.c)

loader_add_test(get_mk_huge_pool_addr
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/get_mk_huge_pool_addr.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_huge_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_huge_pool.c)

loader_add_test(get_mk_page_pool_addr
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/get_mk_page_pool_addr.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_page_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_page_pool.c)

loader_add_test(loader_fini
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/loader_fini.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/loader_init.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_debug_ring.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_debug_ring.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_ext_elf_files.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_args.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_debug_ring.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_elf_file.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_elf_segments.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_huge_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_page_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_stack.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/stop_vmm_per_cpu.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/stop_and_free_the_vmm.c)

loader_add_test(loader_init
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/loader_init.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/loader_fini.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_debug_ring.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_debug_ring.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_ext_elf_files.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_args.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_debug_ring.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_elf_file.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_elf_segments.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_huge_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_page_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_stack.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/stop_vmm_per_cpu.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/stop_and_free_the_vmm.c)

loader_add_test(map_4k_page_rw ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_4k_page_rw.c)
loader_add_test(map_4k_page_rx ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_4k_page_rx.c)

loader_add_test(map_ext_elf_files
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_ext_elf_files.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_4k_page_rw.c)

loader_add_test(map_mk_args
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_args.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_4k_page_rw.c)

loader_add_test(map_mk_debug_ring
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_debug_ring.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_4k_page_rw.c)

loader_add_test(map_mk_elf_file
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_elf_file.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_4k_page_rw.c)

loader_add_test(map_mk_elf_segments
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_elf_segments.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_4k_page_rw.c)

loader_add_test(map_mk_huge_pool
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_huge_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_4k_page_rw.c)

loader_add_test(map_mk_page_pool
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_page_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_4k_page_rw.c)

loader_add_test(map_mk_stack
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_stack.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_4k_page_rw.c)

loader_add_test(serial_write ${CURRENT_FUNCTION_LIST_DIR}/../../src/serial_write.c)

loader_add_test(start_vmm_per_cpu
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/start_vmm_per_cpu.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_and_copy_ext_elf_files_from_user.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_and_copy_mk_elf_file_from_user.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_and_copy_mk_elf_segments.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_args.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_debug_ring.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_huge_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_page_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_stack.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_ext_elf_files.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_args.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_debug_ring.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_elf_file.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_elf_segments.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_huge_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_page_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_stack.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_vmm.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_ext_elf_files.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_args.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_debug_ring.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_elf_file.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_elf_segments.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_huge_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_page_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_stack.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/get_mk_huge_pool_addr.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/get_mk_page_pool_addr.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/loader_fini.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/loader_init.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_4k_page_rw.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_4k_page_rx.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_ext_elf_files.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_args.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_debug_ring.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_elf_file.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_elf_segments.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_huge_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_page_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_stack.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/start_vmm.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/stop_and_free_the_vmm.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/stop_vmm_per_cpu.c)

loader_add_test(start_vmm
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/start_vmm.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_and_copy_ext_elf_files_from_user.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_and_copy_mk_elf_file_from_user.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_and_copy_mk_elf_segments.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_args.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_debug_ring.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_huge_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_page_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_stack.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_ext_elf_files.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_args.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_debug_ring.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_elf_file.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_elf_segments.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_huge_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_page_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_stack.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_vmm.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_ext_elf_files.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_args.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_debug_ring.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_elf_file.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_elf_segments.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_huge_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_page_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_stack.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/get_mk_huge_pool_addr.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/get_mk_page_pool_addr.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/loader_fini.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/loader_init.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_4k_page_rw.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_4k_page_rx.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_ext_elf_files.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_args.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_debug_ring.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_elf_file.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_elf_segments.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_huge_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_page_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_stack.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/start_vmm_per_cpu.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/stop_and_free_the_vmm.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/stop_vmm_per_cpu.c)

loader_add_test(stop_vmm_per_cpu
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/stop_vmm_per_cpu.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_and_copy_ext_elf_files_from_user.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_and_copy_mk_elf_file_from_user.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_and_copy_mk_elf_segments.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_args.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_debug_ring.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_huge_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_page_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_stack.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_ext_elf_files.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_args.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_debug_ring.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_elf_file.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_elf_segments.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_huge_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_page_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_stack.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_vmm.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_ext_elf_files.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_args.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_debug_ring.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_elf_file.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_elf_segments.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_huge_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_page_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_stack.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/get_mk_huge_pool_addr.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/get_mk_page_pool_addr.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/loader_fini.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/loader_init.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_4k_page_rw.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_4k_page_rx.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_ext_elf_files.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_args.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_debug_ring.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_elf_file.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_elf_segments.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_huge_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_page_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_stack.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/start_vmm.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/start_vmm_per_cpu.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/stop_and_free_the_vmm.c)

loader_add_test(stop_vmm
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/stop_vmm.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_and_copy_ext_elf_files_from_user.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_and_copy_mk_elf_file_from_user.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_and_copy_mk_elf_segments.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_args.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_debug_ring.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_huge_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_page_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/alloc_mk_stack.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_ext_elf_files.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_args.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_debug_ring.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_elf_file.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_elf_segments.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_huge_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_page_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_mk_stack.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/dump_vmm.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_ext_elf_files.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_args.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_debug_ring.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_elf_file.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_elf_segments.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_huge_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_page_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/free_mk_stack.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/get_mk_huge_pool_addr.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/get_mk_page_pool_addr.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/loader_fini.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/loader_init.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_4k_page_rw.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_4k_page_rx.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_ext_elf_files.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_args.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_debug_ring.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_elf_file.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_elf_segments.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_huge_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_page_pool.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/map_mk_stack.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/start_vmm.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/start_vmm_per_cpu.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/stop_and_free_the_vmm.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/stop_vmm_per_cpu.c)
