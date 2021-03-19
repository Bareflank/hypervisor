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

include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/function/hypervisor_add_header_depends.cmake)

add_executable(bareflank_efi_loader)

target_include_directories(bareflank_efi_loader PUBLIC
	include
	include/std
	include/platform_interface/c
	../include
	../include/interface/c
	../include/interface/c/bfelf
    ${CMAKE_BINARY_DIR}/include
)

list(APPEND HEADERS
	${CMAKE_CURRENT_LIST_DIR}/include/debug.h
	${CMAKE_CURRENT_LIST_DIR}/include/efi/efi_allocate_type.h
	${CMAKE_CURRENT_LIST_DIR}/include/efi/efi_boot_services.h
	${CMAKE_CURRENT_LIST_DIR}/include/efi/efi_configuration_table.h
	${CMAKE_CURRENT_LIST_DIR}/include/efi/efi_cpu_physical_location2.h
	${CMAKE_CURRENT_LIST_DIR}/include/efi/efi_cpu_physical_location.h
	${CMAKE_CURRENT_LIST_DIR}/include/efi/efi_device_path_protocol.h
	${CMAKE_CURRENT_LIST_DIR}/include/efi/efi_file_info.h
	${CMAKE_CURRENT_LIST_DIR}/include/efi/efi_file_io_token.h
	${CMAKE_CURRENT_LIST_DIR}/include/efi/efi_file_protocol.h
	${CMAKE_CURRENT_LIST_DIR}/include/efi/efi_guid.h
	${CMAKE_CURRENT_LIST_DIR}/include/efi/efi_interface_type.h
	${CMAKE_CURRENT_LIST_DIR}/include/efi/efi_locate_search_type.h
	${CMAKE_CURRENT_LIST_DIR}/include/efi/efi_memory_descriptor.h
	${CMAKE_CURRENT_LIST_DIR}/include/efi/efi_memory_type.h
	${CMAKE_CURRENT_LIST_DIR}/include/efi/efi_mp_services_protocol.h
	${CMAKE_CURRENT_LIST_DIR}/include/efi/efi_open_protocol_information_entry.h
	${CMAKE_CURRENT_LIST_DIR}/include/efi/efi_processor_information.h
	${CMAKE_CURRENT_LIST_DIR}/include/efi/efi_runtime_services.h
	${CMAKE_CURRENT_LIST_DIR}/include/efi/efi_simple_file_system_protocol.h
	${CMAKE_CURRENT_LIST_DIR}/include/efi/efi_simple_text_input_protocol.h
	${CMAKE_CURRENT_LIST_DIR}/include/efi/efi_simple_text_output_mode.h
	${CMAKE_CURRENT_LIST_DIR}/include/efi/efi_simple_text_output_protocol.h
	${CMAKE_CURRENT_LIST_DIR}/include/efi/efi_status.h
	${CMAKE_CURRENT_LIST_DIR}/include/efi/efi_system_table.h
	${CMAKE_CURRENT_LIST_DIR}/include/efi/efi_table_header.h
	${CMAKE_CURRENT_LIST_DIR}/include/efi/efi_time.h
	${CMAKE_CURRENT_LIST_DIR}/include/efi/efi_timer_delay.h
	${CMAKE_CURRENT_LIST_DIR}/include/efi/efi_types.h
	${CMAKE_CURRENT_LIST_DIR}/include/efi/extened_processor_information.h
	${CMAKE_CURRENT_LIST_DIR}/include/types.h
	${CMAKE_CURRENT_LIST_DIR}/include/work_on_cpu_callback_args.h
	${CMAKE_CURRENT_LIST_DIR}/../include/interface/c/bfelf/bfelf_elf64_ehdr_t.h
	${CMAKE_CURRENT_LIST_DIR}/../include/interface/c/bfelf/bfelf_elf64_phdr_t.h
	${CMAKE_CURRENT_LIST_DIR}/../include/interface/c/bfelf/bfelf_types.h
	${CMAKE_CURRENT_LIST_DIR}/../include/interface/c/debug_ring_t.h
	${CMAKE_CURRENT_LIST_DIR}/../include/interface/c/dump_vmm_args_t.h
	${CMAKE_CURRENT_LIST_DIR}/../include/interface/c/mutable_span_t.h
	${CMAKE_CURRENT_LIST_DIR}/../include/interface/c/span_t.h
	${CMAKE_CURRENT_LIST_DIR}/../include/interface/c/start_vmm_args_t.h
	${CMAKE_CURRENT_LIST_DIR}/../include/interface/c/stop_vmm_args_t.h
	${CMAKE_CURRENT_LIST_DIR}/../include/alloc_and_copy_ext_elf_files_from_user.h
	${CMAKE_CURRENT_LIST_DIR}/../include/alloc_and_copy_mk_elf_file_from_user.h
	${CMAKE_CURRENT_LIST_DIR}/../include/alloc_and_copy_mk_elf_segments.h
	${CMAKE_CURRENT_LIST_DIR}/../include/alloc_mk_args.h
	${CMAKE_CURRENT_LIST_DIR}/../include/alloc_mk_debug_ring.h
	${CMAKE_CURRENT_LIST_DIR}/../include/alloc_mk_huge_pool.h
	${CMAKE_CURRENT_LIST_DIR}/../include/alloc_mk_page_pool.h
	${CMAKE_CURRENT_LIST_DIR}/../include/alloc_mk_stack.h
	${CMAKE_CURRENT_LIST_DIR}/../include/dump_ext_elf_files.h
	${CMAKE_CURRENT_LIST_DIR}/../include/dump_mk_args.h
	${CMAKE_CURRENT_LIST_DIR}/../include/dump_mk_debug_ring.h
	${CMAKE_CURRENT_LIST_DIR}/../include/dump_mk_elf_file.h
	${CMAKE_CURRENT_LIST_DIR}/../include/dump_mk_elf_segments.h
	${CMAKE_CURRENT_LIST_DIR}/../include/dump_mk_huge_pool.h
	${CMAKE_CURRENT_LIST_DIR}/../include/dump_mk_page_pool.h
	${CMAKE_CURRENT_LIST_DIR}/../include/dump_mk_stack.h
	${CMAKE_CURRENT_LIST_DIR}/../include/dump_vmm.h
	${CMAKE_CURRENT_LIST_DIR}/../include/elf_segment_t.h
	${CMAKE_CURRENT_LIST_DIR}/../include/free_ext_elf_files.h
	${CMAKE_CURRENT_LIST_DIR}/../include/free_mk_args.h
	${CMAKE_CURRENT_LIST_DIR}/../include/free_mk_debug_ring.h
	${CMAKE_CURRENT_LIST_DIR}/../include/free_mk_elf_file.h
	${CMAKE_CURRENT_LIST_DIR}/../include/free_mk_elf_segments.h
	${CMAKE_CURRENT_LIST_DIR}/../include/free_mk_huge_pool.h
	${CMAKE_CURRENT_LIST_DIR}/../include/free_mk_page_pool.h
	${CMAKE_CURRENT_LIST_DIR}/../include/free_mk_stack.h
	${CMAKE_CURRENT_LIST_DIR}/../include/g_ext_elf_files.h
	${CMAKE_CURRENT_LIST_DIR}/../include/g_mk_args.h
	${CMAKE_CURRENT_LIST_DIR}/../include/g_mk_debug_ring.h
	${CMAKE_CURRENT_LIST_DIR}/../include/g_mk_elf_file.h
	${CMAKE_CURRENT_LIST_DIR}/../include/g_mk_elf_segments.h
	${CMAKE_CURRENT_LIST_DIR}/../include/g_mk_huge_pool.h
	${CMAKE_CURRENT_LIST_DIR}/../include/g_mk_page_pool.h
	${CMAKE_CURRENT_LIST_DIR}/../include/g_mk_stack.h
	${CMAKE_CURRENT_LIST_DIR}/../include/itoa.h
	${CMAKE_CURRENT_LIST_DIR}/../include/loader_fini.h
	${CMAKE_CURRENT_LIST_DIR}/../include/loader_init.h
	${CMAKE_CURRENT_LIST_DIR}/../include/platform.h
	${CMAKE_CURRENT_LIST_DIR}/../include/start_vmm.h
	${CMAKE_CURRENT_LIST_DIR}/../include/start_vmm_per_cpu.h
	${CMAKE_CURRENT_LIST_DIR}/../include/static_assert.h
	${CMAKE_CURRENT_LIST_DIR}/../include/stop_and_free_the_vmm.h
	${CMAKE_CURRENT_LIST_DIR}/../include/stop_vmm.h
	${CMAKE_CURRENT_LIST_DIR}/../include/stop_vmm_per_cpu.h
	${CMAKE_CURRENT_LIST_DIR}/../include/vmm_status.h
)

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    target_include_directories(bareflank_efi_loader PUBLIC
		include/x64
		../include/x64/
		../include/interface/c/x64
    )
	list(APPEND HEADERS
		${CMAKE_CURRENT_LIST_DIR}/../include/interface/c/x64/cpuid_commands.h
		${CMAKE_CURRENT_LIST_DIR}/../include/interface/c/x64/global_descriptor_table_register_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/interface/c/x64/interrupt_descriptor_table_register_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/interface/c/x64/mk_args_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/interface/c/x64/pdpte_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/interface/c/x64/pdte_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/interface/c/x64/pml4te_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/interface/c/x64/pte_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/interface/c/x64/state_save_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/interface/c/x64/tss_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/alloc_and_copy_mk_code_aliases.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/alloc_and_copy_mk_state.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/alloc_and_copy_root_vp_state.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/alloc_mk_root_page_table.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/alloc_pdpt.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/alloc_pdt.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/alloc_pt.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/check_for_hve_support.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/code_aliases_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/demote.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/disable_hve.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/dump_mk_code_aliases.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/dump_mk_root_page_table.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/dump_mk_state.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/dump_root_vp_state.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/enable_hve.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/esr_default.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/esr_df.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/esr_gpf.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/esr_nmi.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/esr_pf.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/free_mk_code_aliases.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/free_mk_root_page_table.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/free_mk_state.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/free_pdpt.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/free_pdt.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/free_pml4t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/free_root_vp_state.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/get_gdt_descriptor_attrib.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/get_gdt_descriptor_base.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/get_gdt_descriptor_limit.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/get_mk_huge_pool_addr.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/get_mk_page_pool_addr.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/g_mk_code_aliases.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/g_mk_root_page_table.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/g_mk_state.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/g_root_vp_state.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/intrinsic_cpuid.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/intrinsic_inb.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/intrinsic_lcr4.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/intrinsic_outb.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/intrinsic_rdmsr.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/intrinsic_scr0.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/intrinsic_scr4.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/intrinsic_scs.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/intrinsic_sds.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/intrinsic_ses.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/intrinsic_sfs.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/intrinsic_sgdt.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/intrinsic_sgs.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/intrinsic_sidt.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/intrinsic_sldtr.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/intrinsic_sss.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/intrinsic_str.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/intrinsic_wrmsr.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/map_4k_page.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/map_4k_page_rw.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/map_4k_page_rx.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/map_ext_elf_files.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/map_mk_args.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/map_mk_code_aliases.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/map_mk_debug_ring.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/map_mk_elf_file.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/map_mk_elf_segments.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/map_mk_huge_pool.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/map_mk_page_pool.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/map_mk_stack.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/map_mk_state.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/map_root_vp_state.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/pdpto.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/pdpt_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/pdto.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/pdt_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/pml4to.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/pml4t_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/promote.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/pto.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/pt_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/send_command_report_off.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/send_command_report_on.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/send_command_stop.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/serial_init.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/serial_write.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/set_gdt_descriptor.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/set_idt_descriptor.h
	)
endif()

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
    target_include_directories(bareflank_efi_loader PUBLIC
		include/x64/amd
		../include/x64/amd
		../include/interface/c/x64/amd
    )
elseif(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    target_include_directories(bareflank_efi_loader PUBLIC
		include/x64/intel
		../include/x64/intel
		../include/interface/c/x64/intel
    )
	list(APPEND HEADERS
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/intel/intrinsic_vmxoff.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/intel/intrinsic_vmxon.h
	)
else()
    message(FATAL_ERROR "Unsupported HYPERVISOR_TARGET_ARCH: ${HYPERVISOR_TARGET_ARCH}")
endif()

target_sources(bareflank_efi_loader PUBLIC
    src/platform.c
	src/entry.c
	../src/alloc_and_copy_ext_elf_files_from_user.c
	../src/alloc_and_copy_mk_elf_file_from_user.c
	../src/alloc_and_copy_mk_elf_segments.c
	../src/alloc_mk_args.c
	../src/alloc_mk_debug_ring.c
	../src/alloc_mk_huge_pool.c
	../src/alloc_mk_page_pool.c
	../src/alloc_mk_stack.c
	../src/dump_ext_elf_files.c
	../src/dump_mk_args.c
	../src/dump_mk_debug_ring.c
	../src/dump_mk_elf_file.c
	../src/dump_mk_elf_segments.c
	../src/dump_mk_huge_pool.c
	../src/dump_mk_page_pool.c
	../src/dump_mk_stack.c
	../src/dump_vmm.c
	../src/free_ext_elf_files.c
	../src/free_mk_args.c
	../src/free_mk_debug_ring.c
	../src/free_mk_elf_file.c
	../src/free_mk_elf_segments.c
	../src/free_mk_huge_pool.c
	../src/free_mk_page_pool.c
	../src/free_mk_stack.c
	../src/g_ext_elf_files.c
	../src/g_mk_args.c
	../src/g_mk_debug_ring.c
	../src/g_mk_elf_file.c
	../src/g_mk_elf_segments.c
	../src/g_mk_huge_pool.c
	../src/g_mk_page_pool.c
	../src/g_mk_stack.c
	../src/loader_fini.c
	../src/loader_init.c
	../src/start_vmm_per_cpu.c
	../src/start_vmm.c
	../src/stop_and_free_the_vmm.c
	../src/stop_vmm_per_cpu.c
	../src/stop_vmm.c
	../src/vmm_status.c
)

hypervisor_add_header_depends(src/platform.c ${HEADERS})
hypervisor_add_header_depends(src/entry.c ${HEADERS})
hypervisor_add_header_depends(../src/alloc_and_copy_ext_elf_files_from_user.c ${HEADERS})
hypervisor_add_header_depends(../src/alloc_and_copy_mk_elf_file_from_user.c ${HEADERS})
hypervisor_add_header_depends(../src/alloc_and_copy_mk_elf_segments.c ${HEADERS})
hypervisor_add_header_depends(../src/alloc_mk_args.c ${HEADERS})
hypervisor_add_header_depends(../src/alloc_mk_debug_ring.c ${HEADERS})
hypervisor_add_header_depends(../src/alloc_mk_huge_pool.c ${HEADERS})
hypervisor_add_header_depends(../src/alloc_mk_page_pool.c ${HEADERS})
hypervisor_add_header_depends(../src/alloc_mk_stack.c ${HEADERS})
hypervisor_add_header_depends(../src/dump_ext_elf_files.c ${HEADERS})
hypervisor_add_header_depends(../src/dump_mk_args.c ${HEADERS})
hypervisor_add_header_depends(../src/dump_mk_debug_ring.c ${HEADERS})
hypervisor_add_header_depends(../src/dump_mk_elf_file.c ${HEADERS})
hypervisor_add_header_depends(../src/dump_mk_elf_segments.c ${HEADERS})
hypervisor_add_header_depends(../src/dump_mk_huge_pool.c ${HEADERS})
hypervisor_add_header_depends(../src/dump_mk_page_pool.c ${HEADERS})
hypervisor_add_header_depends(../src/dump_mk_stack.c ${HEADERS})
hypervisor_add_header_depends(../src/dump_vmm.c ${HEADERS})
hypervisor_add_header_depends(../src/free_ext_elf_files.c ${HEADERS})
hypervisor_add_header_depends(../src/free_mk_args.c ${HEADERS})
hypervisor_add_header_depends(../src/free_mk_debug_ring.c ${HEADERS})
hypervisor_add_header_depends(../src/free_mk_elf_file.c ${HEADERS})
hypervisor_add_header_depends(../src/free_mk_elf_segments.c ${HEADERS})
hypervisor_add_header_depends(../src/free_mk_huge_pool.c ${HEADERS})
hypervisor_add_header_depends(../src/free_mk_page_pool.c ${HEADERS})
hypervisor_add_header_depends(../src/free_mk_stack.c ${HEADERS})
hypervisor_add_header_depends(../src/g_ext_elf_files.c ${HEADERS})
hypervisor_add_header_depends(../src/g_mk_args.c ${HEADERS})
hypervisor_add_header_depends(../src/g_mk_debug_ring.c ${HEADERS})
hypervisor_add_header_depends(../src/g_mk_elf_file.c ${HEADERS})
hypervisor_add_header_depends(../src/g_mk_elf_segments.c ${HEADERS})
hypervisor_add_header_depends(../src/g_mk_huge_pool.c ${HEADERS})
hypervisor_add_header_depends(../src/g_mk_page_pool.c ${HEADERS})
hypervisor_add_header_depends(../src/g_mk_stack.c ${HEADERS})
hypervisor_add_header_depends(../src/loader_fini.c ${HEADERS})
hypervisor_add_header_depends(../src/loader_init.c ${HEADERS})
hypervisor_add_header_depends(../src/start_vmm_per_cpu.c ${HEADERS})
hypervisor_add_header_depends(../src/start_vmm.c ${HEADERS})
hypervisor_add_header_depends(../src/stop_and_free_the_vmm.c ${HEADERS})
hypervisor_add_header_depends(../src/stop_vmm_per_cpu.c ${HEADERS})
hypervisor_add_header_depends(../src/stop_vmm.c ${HEADERS})
hypervisor_add_header_depends(../src/vmm_status.c ${HEADERS})

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    target_sources(bareflank_efi_loader PUBLIC
		src/x64/demote.S
		src/x64/esr_default.S
		src/x64/esr_df.S
		src/x64/esr_gpf.S
		src/x64/esr_nmi.S
		src/x64/esr_pf.S
		src/x64/intrinsic_cpuid.S
		src/x64/intrinsic_inb.S
		src/x64/intrinsic_lcr4.S
		src/x64/intrinsic_outb.S
		src/x64/intrinsic_rdmsr.S
		src/x64/intrinsic_scr0.S
		src/x64/intrinsic_scr4.S
		src/x64/intrinsic_scs.S
		src/x64/intrinsic_sds.S
		src/x64/intrinsic_ses.S
		src/x64/intrinsic_sfs.S
		src/x64/intrinsic_sgdt.S
		src/x64/intrinsic_sgs.S
		src/x64/intrinsic_sidt.S
		src/x64/intrinsic_sldtr.S
		src/x64/intrinsic_sss.S
		src/x64/intrinsic_str.S
		src/x64/intrinsic_wrmsr.S
		src/x64/promote.S
		../src/x64/alloc_and_copy_mk_code_aliases.c
		../src/x64/alloc_and_copy_mk_state.c
		../src/x64/alloc_and_copy_root_vp_state.c
		../src/x64/alloc_mk_root_page_table.c
		../src/x64/alloc_pdpt.c
		../src/x64/alloc_pdt.c
		../src/x64/alloc_pt.c
		../src/x64/dump_mk_code_aliases.c
		../src/x64/dump_mk_root_page_table.c
		../src/x64/dump_mk_state.c
		../src/x64/dump_root_vp_state.c
		../src/x64/free_mk_code_aliases.c
		../src/x64/free_mk_root_page_table.c
		../src/x64/free_mk_state.c
		../src/x64/free_pdpt.c
		../src/x64/free_pdt.c
		../src/x64/free_pml4t.c
		../src/x64/free_root_vp_state.c
		../src/x64/g_mk_code_aliases.c
		../src/x64/g_mk_root_page_table.c
		../src/x64/g_mk_state.c
		../src/x64/g_root_vp_state.c
		../src/x64/get_gdt_descriptor_attrib.c
		../src/x64/get_gdt_descriptor_base.c
		../src/x64/get_gdt_descriptor_limit.c
		../src/x64/get_mk_huge_pool_addr.c
		../src/x64/get_mk_page_pool_addr.c
		../src/x64/map_4k_page_rw.c
		../src/x64/map_4k_page_rx.c
		../src/x64/map_4k_page.c
		../src/x64/map_ext_elf_files.c
		../src/x64/map_mk_args.c
		../src/x64/map_mk_debug_ring.c
		../src/x64/map_mk_code_aliases.c
		../src/x64/map_mk_elf_file.c
		../src/x64/map_mk_elf_segments.c
		../src/x64/map_mk_huge_pool.c
		../src/x64/map_mk_page_pool.c
		../src/x64/map_mk_stack.c
		../src/x64/map_mk_state.c
		../src/x64/map_root_vp_state.c
		../src/x64/send_command_report_off.c
		../src/x64/send_command_report_on.c
		../src/x64/send_command_stop.c
		../src/x64/serial_init.c
		../src/x64/serial_write.c
		../src/x64/set_gdt_descriptor.c
		../src/x64/set_idt_descriptor.c
    )

	hypervisor_add_header_depends(../src/x64/alloc_and_copy_mk_code_aliases.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/alloc_and_copy_mk_state.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/alloc_and_copy_root_vp_state.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/alloc_mk_root_page_table.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/alloc_pdpt.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/alloc_pdt.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/alloc_pt.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/dump_mk_code_aliases.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/dump_mk_root_page_table.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/dump_mk_state.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/dump_root_vp_state.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/free_mk_code_aliases.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/free_mk_root_page_table.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/free_mk_state.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/free_pdpt.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/free_pdt.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/free_pml4t.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/free_root_vp_state.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/g_mk_code_aliases.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/g_mk_root_page_table.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/g_mk_state.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/g_root_vp_state.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/get_gdt_descriptor_attrib.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/get_gdt_descriptor_base.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/get_gdt_descriptor_limit.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/get_mk_huge_pool_addr.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/get_mk_page_pool_addr.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/map_4k_page_rw.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/map_4k_page_rx.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/map_4k_page.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/map_ext_elf_files.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/map_mk_args.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/map_mk_debug_ring.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/map_mk_code_aliases.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/map_mk_elf_file.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/map_mk_elf_segments.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/map_mk_huge_pool.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/map_mk_page_pool.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/map_mk_stack.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/map_mk_state.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/map_root_vp_state.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/send_command_report_off.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/send_command_report_on.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/send_command_stop.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/serial_init.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/serial_write.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/set_gdt_descriptor.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/set_idt_descriptor.c ${HEADERS})
endif()

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
    target_sources(bareflank_efi_loader PUBLIC
		src/x64/amd/disable_interrupts.S
		src/x64/amd/enable_interrupts.S
		../src/x64/amd/enable_hve.c
		../src/x64/amd/disable_hve.c
		../src/x64/amd/check_for_hve_support.c
    )
	hypervisor_add_header_depends(../src/x64/amd/enable_hve.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/amd/disable_hve.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/amd/check_for_hve_support.c ${HEADERS})
elseif(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    target_sources(bareflank_efi_loader PUBLIC
		src/x64/intel/disable_interrupts.S
		src/x64/intel/enable_interrupts.S
		src/x64/intel/intrinsic_vmxoff.S
		src/x64/intel/intrinsic_vmxon.S
		../src/x64/intel/enable_hve.c
		../src/x64/intel/disable_hve.c
		../src/x64/intel/check_for_hve_support.c
    )
	hypervisor_add_header_depends(../src/x64/intel/enable_hve.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/intel/disable_hve.c ${HEADERS})
	hypervisor_add_header_depends(../src/x64/intel/check_for_hve_support.c ${HEADERS})
else()
    message(FATAL_ERROR "Unsupported HYPERVISOR_TARGET_ARCH: ${HYPERVISOR_TARGET_ARCH}")
endif()

install(TARGETS bareflank_efi_loader DESTINATION bin)
