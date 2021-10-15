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

add_library(loader_tests_x64)

target_include_directories(loader_tests_x64 PRIVATE
    ${COMMON_INCLUDES}
)

target_include_directories(loader_tests_x64 PRIVATE SYSTEM
    ${COMMON_SYSTEM_INCLUDES}
)

target_sources(loader_tests_x64 PRIVATE
    ${CURRENT_FUNCTION_LIST_DIR}/../platform.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/g_mut_mk_code_aliases.c
)

target_compile_definitions(loader_tests_x64 PRIVATE
    ${COMMON_DEFINES}
)

# ------------------------------------------------------------------------------
# Macros For This Directory
# ------------------------------------------------------------------------------

macro(loader_add_test NAME)
    bf_add_test(
        test_${NAME}
        SOURCES ${ARGN}
        INCLUDES ${X64_INCLUDES}
        SYSTEM_INCLUDES ${X64_SYSTEM_INCLUDES}
        DEFINES ${X64_DEFINES}
        DEFINES DEBUG_LOADER
        LIBRARIES loader_tests_x64
    )
endmacro(loader_add_test)

# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------

loader_add_test(alloc_and_copy_mk_code_aliases
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_and_copy_mk_code_aliases.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_mk_code_aliases.c)

loader_add_test(alloc_and_copy_mk_state
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_and_copy_mk_state.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_mk_state.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/set_gdt_descriptor.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/set_idt_descriptor.c)

loader_add_test(alloc_and_copy_root_vp_state
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_and_copy_root_vp_state.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_root_vp_state.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/get_gdt_descriptor_limit.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/get_gdt_descriptor_base.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/get_gdt_descriptor_attrib.c)

loader_add_test(alloc_mk_root_page_table
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_mk_root_page_table.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_mk_root_page_table.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_pdpt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_pdt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_pt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_pml4t.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_pdpt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_pdt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/map_4k_page_rw.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/map_4k_page.c)

loader_add_test(alloc_pdpt
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_pdpt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_pml4t.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_pdpt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_pdt.c)

loader_add_test(alloc_pdt
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_pdt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_pdpt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_pdt.c)

loader_add_test(alloc_pt
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_pt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_pdt.c)

loader_add_test(dump_mk_code_aliases ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/dump_mk_code_aliases.c)
loader_add_test(dump_mk_state ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/dump_mk_state.c)
loader_add_test(dump_root_vp_state ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/dump_root_vp_state.c)

loader_add_test(free_mk_code_aliases
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_mk_code_aliases.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_and_copy_mk_code_aliases.c)

loader_add_test(free_mk_root_page_table
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_mk_root_page_table.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_mk_root_page_table.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_pdpt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_pdt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_pt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_pml4t.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_pdpt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_pdt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/map_4k_page_rw.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/map_4k_page.c)

loader_add_test(free_mk_state
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_mk_state.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_and_copy_mk_state.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/set_gdt_descriptor.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/set_idt_descriptor.c)

loader_add_test(free_root_vp_state
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_root_vp_state.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_and_copy_root_vp_state.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/get_gdt_descriptor_limit.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/get_gdt_descriptor_base.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/get_gdt_descriptor_attrib.c)

loader_add_test(free_pml4t
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_pml4t.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_pdpt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_pdpt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_pdt.c)

loader_add_test(free_pdpt
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_pdt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_pdpt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_pdt.c)

loader_add_test(free_pdt
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_pdt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_pt.c)

loader_add_test(get_gdt_descriptor_attrib ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/get_gdt_descriptor_attrib.c)
loader_add_test(get_gdt_descriptor_base ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/get_gdt_descriptor_base.c)
loader_add_test(get_gdt_descriptor_limit ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/get_gdt_descriptor_limit.c)

loader_add_test(map_4k_page
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/map_4k_page.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_mk_root_page_table.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_pdpt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_pdt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_pt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_pml4t.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_pdpt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_pdt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_mk_root_page_table.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/map_4k_page_rw.c)

if(NOT WIN32 AND NOT HYPERVISOR_IWYU)
    loader_add_test(map_mk_code_aliases
        ${CURRENT_FUNCTION_LIST_DIR}/demote.S
        ${CURRENT_FUNCTION_LIST_DIR}/esr_default.S
        ${CURRENT_FUNCTION_LIST_DIR}/esr_df.S
        ${CURRENT_FUNCTION_LIST_DIR}/esr_gpf.S
        ${CURRENT_FUNCTION_LIST_DIR}/esr_nmi.S
        ${CURRENT_FUNCTION_LIST_DIR}/esr_pf.S
        ${CURRENT_FUNCTION_LIST_DIR}/promote.S
        ${CURRENT_FUNCTION_LIST_DIR}/serial_write_c.S
        ${CURRENT_FUNCTION_LIST_DIR}/serial_write_hex.S
        ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/map_mk_code_aliases.c
        ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_and_copy_mk_code_aliases.c
        ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_mk_root_page_table.c
        ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_pdpt.c
        ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_pdt.c
        ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_pt.c
        ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_pml4t.c
        ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_pdpt.c
        ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_pdt.c
        ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_mk_code_aliases.c
        ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_mk_root_page_table.c
        ${CURRENT_FUNCTION_LIST_DIR}/../../../src/map_4k_page_rw.c
        ${CURRENT_FUNCTION_LIST_DIR}/../../../src/map_4k_page_rx.c
        ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/map_4k_page.c)
endif()

loader_add_test(map_mk_state
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/map_mk_state.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_and_copy_mk_state.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_mk_root_page_table.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_pdpt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_pdt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_pt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_pml4t.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_pdpt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_pdt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_mk_state.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_mk_root_page_table.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/map_4k_page_rw.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/map_4k_page.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/set_gdt_descriptor.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/set_idt_descriptor.c)

loader_add_test(map_root_vp_state
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/map_root_vp_state.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_and_copy_root_vp_state.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_mk_root_page_table.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_pdpt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_pdt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/alloc_pt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_pml4t.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_pdpt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_pdt.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_root_vp_state.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/free_mk_root_page_table.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/get_gdt_descriptor_limit.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/get_gdt_descriptor_base.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/get_gdt_descriptor_attrib.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/map_4k_page_rw.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/map_4k_page.c)

loader_add_test(send_command_report_off ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/send_command_report_off.c)
loader_add_test(send_command_report_on ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/send_command_report_on.c)
loader_add_test(send_command_stop ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/send_command_stop.c)
loader_add_test(serial_init ${CURRENT_FUNCTION_LIST_DIR}/../../../src/x64/serial_init.c)
