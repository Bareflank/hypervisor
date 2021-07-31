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

include(${bsl_SOURCE_DIR}/cmake/function/bf_add_test.cmake)

# ------------------------------------------------------------------------------
# Includes
# ------------------------------------------------------------------------------

list(APPEND INCLUDES
    ${CMAKE_CURRENT_LIST_DIR}/common_platform
)

list(APPEND SYSTEM_INCLUDES
    ${CMAKE_CURRENT_LIST_DIR}/../include
    ${CMAKE_CURRENT_LIST_DIR}/../include/interface/c
)

list(APPEND COMMON_INCLUDES
    ${INCLUDES}
    ${CMAKE_CURRENT_LIST_DIR}/common_arch
    ${CMAKE_CURRENT_LIST_DIR}/common_arch/interface/c
)

list(APPEND COMMON_SYSTEM_INCLUDES
    ${SYSTEM_INCLUDES}
)

list(APPEND X64_INCLUDES
    ${INCLUDES}
    ${CMAKE_CURRENT_LIST_DIR}/../include/x64
    ${CMAKE_CURRENT_LIST_DIR}/../include/interface/x64
)

list(APPEND X64_SYSTEM_INCLUDES
    ${SYSTEM_INCLUDES}
)

list(APPEND AMD_INCLUDES
    ${X64_INCLUDES}
    ${CMAKE_CURRENT_LIST_DIR}/../include/x64/amd
    ${CMAKE_CURRENT_LIST_DIR}/../include/interface/x64/amd
)

list(APPEND AMD_SYSTEM_INCLUDES
    ${X64_SYSTEM_INCLUDES}
)

list(APPEND INTEL_INCLUDES
    ${X64_INCLUDES}
    ${CMAKE_CURRENT_LIST_DIR}/../include/x64/intel
    ${CMAKE_CURRENT_LIST_DIR}/../include/interface/x64/intel
)

list(APPEND INTEL_SYSTEM_INCLUDES
    ${X64_SYSTEM_INCLUDES}
)

list(APPEND AARCH64_INCLUDES
    ${INCLUDES}
    ${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64
    ${CMAKE_CURRENT_LIST_DIR}/../include/interface/arm/aarch64
)

list(APPEND AARCH64_SYSTEM_INCLUDES
    ${SYSTEM_INCLUDES}
)

# ------------------------------------------------------------------------------
# Definitions
# ------------------------------------------------------------------------------

list(APPEND DEFINES
    HYPERVISOR_DEBUG_RING_SIZE=0x7FF0
    HYPERVISOR_MAX_EXTENSIONS=2
    HYPERVISOR_MAX_SEGMENTS=3
)

# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------

add_subdirectory(alloc_and_copy_ext_elf_files_from_user)
add_subdirectory(alloc_and_copy_mk_elf_file_from_user)
add_subdirectory(alloc_and_copy_mk_elf_segments)
add_subdirectory(alloc_mk_args)
add_subdirectory(alloc_mk_debug_ring)
add_subdirectory(alloc_mk_huge_pool)
add_subdirectory(alloc_mk_page_pool)
add_subdirectory(alloc_mk_stack)
add_subdirectory(dump_ext_elf_files)
add_subdirectory(dump_mk_args)
add_subdirectory(dump_mk_debug_ring)
add_subdirectory(dump_mk_elf_file)
add_subdirectory(dump_mk_elf_segments)
add_subdirectory(dump_mk_huge_pool)
add_subdirectory(dump_mk_page_pool)
add_subdirectory(dump_mk_root_page_table)
add_subdirectory(dump_mk_stack)
add_subdirectory(dump_vmm)
add_subdirectory(free_ext_elf_files)
add_subdirectory(free_mk_args)
add_subdirectory(free_mk_debug_ring)
add_subdirectory(free_mk_elf_file)
add_subdirectory(free_mk_elf_segments)
add_subdirectory(free_mk_huge_pool)
add_subdirectory(free_mk_page_pool)
add_subdirectory(free_mk_stack)
add_subdirectory(g_cpu_status)
add_subdirectory(get_mk_huge_pool_addr)
add_subdirectory(get_mk_page_pool_addr)
add_subdirectory(g_ext_elf_files)
add_subdirectory(g_mk_args)
add_subdirectory(g_mk_code_aliases)
add_subdirectory(g_mk_debug_ring)
add_subdirectory(g_mk_elf_file)
add_subdirectory(g_mk_elf_segments)
add_subdirectory(g_mk_huge_pool)
add_subdirectory(g_mk_page_pool)
add_subdirectory(g_mk_root_page_table)
add_subdirectory(g_mk_stack)
add_subdirectory(g_mk_state)
add_subdirectory(g_root_vp_state)
add_subdirectory(g_vmm_status)
add_subdirectory(loader_fini)
add_subdirectory(loader_init)
add_subdirectory(map_4k_page_rw)
add_subdirectory(map_4k_page_rx)
add_subdirectory(map_ext_elf_files)
add_subdirectory(map_mk_args)
add_subdirectory(map_mk_debug_ring)
add_subdirectory(map_mk_elf_file)
add_subdirectory(map_mk_elf_segments)
add_subdirectory(map_mk_huge_pool)
add_subdirectory(map_mk_page_pool)
add_subdirectory(map_mk_stack)
add_subdirectory(serial_write)
add_subdirectory(start_vmm)
add_subdirectory(start_vmm_per_cpu)
add_subdirectory(stop_and_free_the_vmm)
add_subdirectory(stop_vmm)
add_subdirectory(stop_vmm_per_cpu)

add_subdirectory(x64/alloc_and_copy_mk_code_aliases)
add_subdirectory(x64/alloc_and_copy_mk_state)
add_subdirectory(x64/alloc_and_copy_root_vp_state)
add_subdirectory(x64/alloc_mk_root_page_table)
add_subdirectory(x64/alloc_pdpt)
add_subdirectory(x64/alloc_pdt)
add_subdirectory(x64/alloc_pt)
add_subdirectory(x64/dump_mk_code_aliases)
add_subdirectory(x64/dump_mk_state)
add_subdirectory(x64/dump_root_vp_state)
add_subdirectory(x64/free_mk_code_aliases)
add_subdirectory(x64/free_mk_root_page_table)
add_subdirectory(x64/free_mk_state)
add_subdirectory(x64/free_pdpt)
add_subdirectory(x64/free_pdt)
add_subdirectory(x64/free_pml4t)
add_subdirectory(x64/free_root_vp_state)
add_subdirectory(x64/get_gdt_descriptor_attrib)
add_subdirectory(x64/get_gdt_descriptor_base)
add_subdirectory(x64/get_gdt_descriptor_limit)
add_subdirectory(x64/map_4k_page)
add_subdirectory(x64/map_mk_code_aliases)
add_subdirectory(x64/map_mk_state)
add_subdirectory(x64/map_root_vp_state)
add_subdirectory(x64/send_command_report_off)
add_subdirectory(x64/send_command_report_on)
add_subdirectory(x64/send_command_stop)
add_subdirectory(x64/serial_init)
add_subdirectory(x64/set_gdt_descriptor)
add_subdirectory(x64/set_idt_descriptor)
add_subdirectory(x64/amd/check_cpu_configuration)
add_subdirectory(x64/amd/disable_hve)
add_subdirectory(x64/amd/enable_hve)
add_subdirectory(x64/intel/check_cpu_configuration)
add_subdirectory(x64/intel/disable_hve)
add_subdirectory(x64/intel/enable_hve)

add_subdirectory(arm/aarch64/alloc_and_copy_mk_code_aliases)
add_subdirectory(arm/aarch64/alloc_and_copy_mk_state)
add_subdirectory(arm/aarch64/alloc_and_copy_root_vp_state)
add_subdirectory(arm/aarch64/alloc_l1t)
add_subdirectory(arm/aarch64/alloc_l2t)
add_subdirectory(arm/aarch64/alloc_l3t)
add_subdirectory(arm/aarch64/alloc_mk_root_page_table)
add_subdirectory(arm/aarch64/check_cpu_configuration)
add_subdirectory(arm/aarch64/dump_mk_code_aliases)
add_subdirectory(arm/aarch64/dump_mk_state)
add_subdirectory(arm/aarch64/dump_root_vp_state)
add_subdirectory(arm/aarch64/free_l0t)
add_subdirectory(arm/aarch64/free_l1t)
add_subdirectory(arm/aarch64/free_l2t)
add_subdirectory(arm/aarch64/free_mk_code_aliases)
add_subdirectory(arm/aarch64/free_mk_root_page_table)
add_subdirectory(arm/aarch64/free_mk_state)
add_subdirectory(arm/aarch64/free_root_vp_state)
add_subdirectory(arm/aarch64/map_4k_page)
add_subdirectory(arm/aarch64/map_mk_code_aliases)
add_subdirectory(arm/aarch64/map_mk_state)
add_subdirectory(arm/aarch64/map_root_vp_state)
add_subdirectory(arm/aarch64/send_command_report_off)
add_subdirectory(arm/aarch64/send_command_report_on)
add_subdirectory(arm/aarch64/send_command_stop)
add_subdirectory(arm/aarch64/serial_init)

add_subdirectory(efi/entry)
add_subdirectory(efi/platform)
add_subdirectory(efi/work_on_cpu_callback)

add_subdirectory(efi/x64/arch_init)
add_subdirectory(efi/x64/arch_locate_protocols)
add_subdirectory(efi/x64/arch_num_online_cpus)
add_subdirectory(efi/x64/arch_work_on_cpu)
add_subdirectory(efi/x64/setup_tss)
add_subdirectory(efi/x64/amd/setup_cr0)
add_subdirectory(efi/x64/amd/setup_cr4)
add_subdirectory(efi/x64/intel/setup_cr0)
add_subdirectory(efi/x64/intel/setup_cr4)

add_subdirectory(efi/arm/aarch64/arch_init)
add_subdirectory(efi/arm/aarch64/arch_locate_protocols)
add_subdirectory(efi/arm/aarch64/arch_num_online_cpus)
add_subdirectory(efi/arm/aarch64/arch_work_on_cpu)
