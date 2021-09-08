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

include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/function/hypervisor_target_source.cmake)

add_executable(bareflank_efi_loader)

# ------------------------------------------------------------------------------
# Includes
# ------------------------------------------------------------------------------

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
	if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
		target_include_directories(bareflank_efi_loader PUBLIC
			include/x64/amd
			../include/x64/amd
			../include/interface/x64/amd
		)
	endif()

	if(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
		target_include_directories(bareflank_efi_loader PUBLIC
			include/x64/intel
			../include/x64/intel
			../include/interface/x64/intel
		)
	endif()

    target_include_directories(bareflank_efi_loader PUBLIC
		include/x64
		../include/x64/
		../include/interface/x64
    )
endif()

if(HYPERVISOR_TARGET_ARCH STREQUAL "aarch64")
	target_include_directories(bareflank_efi_loader PUBLIC
		include/arm/aarch64
		../include/arm/aarch64
		../include/interface/arm/aarch64
	)
endif()

target_include_directories(bareflank_efi_loader PUBLIC
	include
	include/std
	include/platform_interface
	../include
	../include/interface
    ${CMAKE_BINARY_DIR}/include
)

# ------------------------------------------------------------------------------
# Headers
# ------------------------------------------------------------------------------

list(APPEND HEADERS
	${CMAKE_CURRENT_LIST_DIR}/include/arch_init.h
	${CMAKE_CURRENT_LIST_DIR}/include/arch_locate_protocols.h
	${CMAKE_CURRENT_LIST_DIR}/include/arch_num_online_cpus.h
	${CMAKE_CURRENT_LIST_DIR}/include/arch_work_on_cpu.h
	${CMAKE_CURRENT_LIST_DIR}/include/debug.h
	${CMAKE_CURRENT_LIST_DIR}/include/types.h
	${CMAKE_CURRENT_LIST_DIR}/include/work_on_cpu_callback_args.h
	${CMAKE_CURRENT_LIST_DIR}/include/work_on_cpu_callback.h
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
	${CMAKE_CURRENT_LIST_DIR}/include/efi/efi_loaded_image_protocol.h
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
	${CMAKE_CURRENT_LIST_DIR}/../include/alloc_and_copy_ext_elf_files_from_user.h
	${CMAKE_CURRENT_LIST_DIR}/../include/alloc_and_copy_mk_code_aliases.h
	${CMAKE_CURRENT_LIST_DIR}/../include/alloc_and_copy_mk_elf_file_from_user.h
	${CMAKE_CURRENT_LIST_DIR}/../include/alloc_and_copy_mk_elf_segments.h
	${CMAKE_CURRENT_LIST_DIR}/../include/alloc_and_copy_mk_state.h
	${CMAKE_CURRENT_LIST_DIR}/../include/alloc_and_copy_root_vp_state.h
	${CMAKE_CURRENT_LIST_DIR}/../include/alloc_mk_args.h
	${CMAKE_CURRENT_LIST_DIR}/../include/alloc_mk_debug_ring.h
	${CMAKE_CURRENT_LIST_DIR}/../include/alloc_mk_huge_pool.h
	${CMAKE_CURRENT_LIST_DIR}/../include/alloc_mk_page_pool.h
	${CMAKE_CURRENT_LIST_DIR}/../include/alloc_mk_root_page_table.h
	${CMAKE_CURRENT_LIST_DIR}/../include/alloc_mk_stack.h
	${CMAKE_CURRENT_LIST_DIR}/../include/check_cpu_configuration.h
	${CMAKE_CURRENT_LIST_DIR}/../include/demote.h
	${CMAKE_CURRENT_LIST_DIR}/../include/dump_ext_elf_files.h
	${CMAKE_CURRENT_LIST_DIR}/../include/dump_mk_args.h
	${CMAKE_CURRENT_LIST_DIR}/../include/dump_mk_code_aliases.h
	${CMAKE_CURRENT_LIST_DIR}/../include/dump_mk_debug_ring.h
	${CMAKE_CURRENT_LIST_DIR}/../include/dump_mk_elf_file.h
	${CMAKE_CURRENT_LIST_DIR}/../include/dump_mk_elf_segments.h
	${CMAKE_CURRENT_LIST_DIR}/../include/dump_mk_huge_pool.h
	${CMAKE_CURRENT_LIST_DIR}/../include/dump_mk_page_pool.h
	${CMAKE_CURRENT_LIST_DIR}/../include/dump_mk_root_page_table.h
	${CMAKE_CURRENT_LIST_DIR}/../include/dump_mk_stack.h
	${CMAKE_CURRENT_LIST_DIR}/../include/dump_mk_state.h
	${CMAKE_CURRENT_LIST_DIR}/../include/dump_root_vp_state.h
	${CMAKE_CURRENT_LIST_DIR}/../include/dump_vmm.h
	${CMAKE_CURRENT_LIST_DIR}/../include/dump_vmm_on_error_if_needed.h
	${CMAKE_CURRENT_LIST_DIR}/../include/elf_segment_t.h
	${CMAKE_CURRENT_LIST_DIR}/../include/flush_cache.h
	${CMAKE_CURRENT_LIST_DIR}/../include/free_ext_elf_files.h
	${CMAKE_CURRENT_LIST_DIR}/../include/free_mk_args.h
	${CMAKE_CURRENT_LIST_DIR}/../include/free_mk_code_aliases.h
	${CMAKE_CURRENT_LIST_DIR}/../include/free_mk_debug_ring.h
	${CMAKE_CURRENT_LIST_DIR}/../include/free_mk_elf_file.h
	${CMAKE_CURRENT_LIST_DIR}/../include/free_mk_elf_segments.h
	${CMAKE_CURRENT_LIST_DIR}/../include/free_mk_huge_pool.h
	${CMAKE_CURRENT_LIST_DIR}/../include/free_mk_page_pool.h
	${CMAKE_CURRENT_LIST_DIR}/../include/free_mk_root_page_table.h
	${CMAKE_CURRENT_LIST_DIR}/../include/free_mk_stack.h
	${CMAKE_CURRENT_LIST_DIR}/../include/free_mk_state.h
	${CMAKE_CURRENT_LIST_DIR}/../include/free_root_vp_state.h
	${CMAKE_CURRENT_LIST_DIR}/../include/g_cpu_status.h
	${CMAKE_CURRENT_LIST_DIR}/../include/get_mk_huge_pool_addr.h
	${CMAKE_CURRENT_LIST_DIR}/../include/get_mk_page_pool_addr.h
	${CMAKE_CURRENT_LIST_DIR}/../include/g_ext_elf_files.h
	${CMAKE_CURRENT_LIST_DIR}/../include/g_mk_args.h
	${CMAKE_CURRENT_LIST_DIR}/../include/g_mk_code_aliases.h
	${CMAKE_CURRENT_LIST_DIR}/../include/g_mk_debug_ring.h
	${CMAKE_CURRENT_LIST_DIR}/../include/g_mk_elf_file.h
	${CMAKE_CURRENT_LIST_DIR}/../include/g_mk_elf_segments.h
	${CMAKE_CURRENT_LIST_DIR}/../include/g_mk_huge_pool.h
	${CMAKE_CURRENT_LIST_DIR}/../include/g_mk_page_pool.h
	${CMAKE_CURRENT_LIST_DIR}/../include/g_mk_root_page_table.h
	${CMAKE_CURRENT_LIST_DIR}/../include/g_mk_stack.h
	${CMAKE_CURRENT_LIST_DIR}/../include/g_mk_state.h
	${CMAKE_CURRENT_LIST_DIR}/../include/g_root_vp_state.h
	${CMAKE_CURRENT_LIST_DIR}/../include/g_vmm_status.h
	${CMAKE_CURRENT_LIST_DIR}/../include/itoa.h
	${CMAKE_CURRENT_LIST_DIR}/../include/loader_fini.h
	${CMAKE_CURRENT_LIST_DIR}/../include/loader_init.h
	${CMAKE_CURRENT_LIST_DIR}/../include/map_4k_page.h
	${CMAKE_CURRENT_LIST_DIR}/../include/map_4k_page_rw.h
	${CMAKE_CURRENT_LIST_DIR}/../include/map_4k_page_rx.h
	${CMAKE_CURRENT_LIST_DIR}/../include/map_ext_elf_files.h
	${CMAKE_CURRENT_LIST_DIR}/../include/map_mk_args.h
	${CMAKE_CURRENT_LIST_DIR}/../include/map_mk_code_aliases.h
	${CMAKE_CURRENT_LIST_DIR}/../include/map_mk_debug_ring.h
	${CMAKE_CURRENT_LIST_DIR}/../include/map_mk_elf_file.h
	${CMAKE_CURRENT_LIST_DIR}/../include/map_mk_elf_segments.h
	${CMAKE_CURRENT_LIST_DIR}/../include/map_mk_huge_pool.h
	${CMAKE_CURRENT_LIST_DIR}/../include/map_mk_page_pool.h
	${CMAKE_CURRENT_LIST_DIR}/../include/map_mk_stack.h
	${CMAKE_CURRENT_LIST_DIR}/../include/map_mk_state.h
	${CMAKE_CURRENT_LIST_DIR}/../include/map_root_vp_state.h
	${CMAKE_CURRENT_LIST_DIR}/../include/mutable_span_t.h
	${CMAKE_CURRENT_LIST_DIR}/../include/platform.h
	${CMAKE_CURRENT_LIST_DIR}/../include/promote.h
	${CMAKE_CURRENT_LIST_DIR}/../include/send_command_report_off.h
	${CMAKE_CURRENT_LIST_DIR}/../include/send_command_report_on.h
	${CMAKE_CURRENT_LIST_DIR}/../include/send_command_stop.h
	${CMAKE_CURRENT_LIST_DIR}/../include/serial_init.h
	${CMAKE_CURRENT_LIST_DIR}/../include/serial_write_c.h
	${CMAKE_CURRENT_LIST_DIR}/../include/serial_write_hex.h
	${CMAKE_CURRENT_LIST_DIR}/../include/serial_write.h
	${CMAKE_CURRENT_LIST_DIR}/../include/span_t.h
	${CMAKE_CURRENT_LIST_DIR}/../include/start_vmm.h
	${CMAKE_CURRENT_LIST_DIR}/../include/start_vmm_per_cpu.h
	${CMAKE_CURRENT_LIST_DIR}/../include/stop_and_free_the_vmm.h
	${CMAKE_CURRENT_LIST_DIR}/../include/stop_vmm.h
	${CMAKE_CURRENT_LIST_DIR}/../include/stop_vmm_per_cpu.h
	${CMAKE_CURRENT_LIST_DIR}/../include/bfelf/bfelf_elf64_ehdr_t.h
	${CMAKE_CURRENT_LIST_DIR}/../include/bfelf/bfelf_elf64_phdr_t.h
	${CMAKE_CURRENT_LIST_DIR}/../include/bfelf/bfelf_elf64_shdr_t.h
	${CMAKE_CURRENT_LIST_DIR}/../include/interface/debug_ring_t.h
	${CMAKE_CURRENT_LIST_DIR}/../include/interface/dump_vmm_args_t.h
	${CMAKE_CURRENT_LIST_DIR}/../include/interface/mk_args_t.h
	${CMAKE_CURRENT_LIST_DIR}/../include/interface/start_vmm_args_t.h
	${CMAKE_CURRENT_LIST_DIR}/../include/interface/stop_vmm_args_t.h
)

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
	list(APPEND HEADERS
		${CMAKE_CURRENT_LIST_DIR}/include/x64/setup_cr0.h
		${CMAKE_CURRENT_LIST_DIR}/include/x64/setup_cr4.h
		${CMAKE_CURRENT_LIST_DIR}/include/x64/setup_tss.h
		${CMAKE_CURRENT_LIST_DIR}/../include/interface/x64/cpuid_commands.h
		${CMAKE_CURRENT_LIST_DIR}/../include/interface/x64/global_descriptor_table_register_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/interface/x64/interrupt_descriptor_table_register_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/interface/x64/state_save_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/interface/x64/tss_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/alloc_pdpt.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/alloc_pdt.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/alloc_pt.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/code_aliases_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/disable_hve.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/enable_hve.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/esr_default.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/esr_df.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/esr_gpf.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/esr_nmi.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/esr_pf.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/free_pdpt.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/free_pdt.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/free_pml4t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/get_gdt_descriptor_attrib.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/get_gdt_descriptor_base.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/get_gdt_descriptor_limit.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/intrinsic_cpuid.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/intrinsic_inb.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/intrinsic_lcr0.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/intrinsic_lcr4.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/intrinsic_lgdt.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/intrinsic_ltr.h
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
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/pdpto.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/pdpt_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/pdpte_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/pdto.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/pdt_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/pdte_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/pml4to.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/pml4t_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/pml4te_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/pto.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/pt_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/pte_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/root_page_table_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/set_gdt_descriptor.h
		${CMAKE_CURRENT_LIST_DIR}/../include/x64/set_idt_descriptor.h
	)

	if(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
		list(APPEND HEADERS
			${CMAKE_CURRENT_LIST_DIR}/../include/x64/intel/intrinsic_vmxoff.h
			${CMAKE_CURRENT_LIST_DIR}/../include/x64/intel/intrinsic_vmxon.h
		)
	endif()
endif()

if(HYPERVISOR_TARGET_ARCH STREQUAL "aarch64")
	list(APPEND HEADERS
		${CMAKE_CURRENT_LIST_DIR}/../include/interface/arm/aarch64/cpuid_commands.h
		${CMAKE_CURRENT_LIST_DIR}/../include/interface/arm/aarch64/state_save_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64/alloc_l1t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64/alloc_l2t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64/alloc_l3t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64/code_aliases_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64/free_l0t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64/free_l1t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64/free_l2t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64/l0to.h
		${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64/l0t_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64/l0te_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64/l1to.h
		${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64/l1t_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64/l1te_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64/l2to.h
		${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64/l2t_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64/l2te_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64/l3to.h
		${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64/l3t_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64/l3te_t.h
		${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64/read_currentel.h
		${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64/read_daif.h
		${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64/read_hcr_el2.h
		${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64/read_mair_el2.h
		${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64/read_sctlr_el2.h
		${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64/read_spsel.h
		${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64/read_tcr_el2.h
		${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64/read_ttbr0_el2.h
		${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64/read_vbar_el2.h
		${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64/root_page_table_t.h
	)
endif()

# ------------------------------------------------------------------------------
# Sources
# ------------------------------------------------------------------------------

hypervisor_target_source(bareflank_efi_loader src/entry.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader src/platform.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader src/work_on_cpu_callback.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/alloc_and_copy_ext_elf_files_from_user.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/alloc_and_copy_mk_elf_file_from_user.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/alloc_and_copy_mk_elf_segments.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/alloc_mk_args.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/alloc_mk_debug_ring.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/alloc_mk_huge_pool.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/alloc_mk_page_pool.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/alloc_mk_stack.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/dump_ext_elf_files.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/dump_mk_args.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/dump_mk_debug_ring.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/dump_mk_elf_file.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/dump_mk_elf_segments.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/dump_mk_huge_pool.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/dump_mk_page_pool.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/dump_mk_root_page_table.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/dump_mk_stack.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/dump_vmm.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/free_ext_elf_files.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/free_mk_args.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/free_mk_debug_ring.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/free_mk_elf_file.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/free_mk_elf_segments.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/free_mk_huge_pool.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/free_mk_page_pool.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/free_mk_stack.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/g_cpu_status.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/get_mk_huge_pool_addr.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/get_mk_page_pool_addr.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/g_ext_elf_files.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/g_mk_args.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/g_mk_code_aliases.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/g_mk_debug_ring.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/g_mk_elf_file.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/g_mk_elf_segments.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/g_mk_huge_pool.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/g_mk_page_pool.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/g_mk_root_page_table.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/g_mk_stack.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/g_mk_state.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/g_root_vp_state.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/g_vmm_status.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/loader_fini.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/loader_init.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/map_4k_page_rw.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/map_4k_page_rx.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/map_ext_elf_files.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/map_mk_args.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/map_mk_debug_ring.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/map_mk_elf_file.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/map_mk_elf_segments.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/map_mk_huge_pool.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/map_mk_page_pool.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/map_mk_stack.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/serial_write.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/start_vmm.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/start_vmm_per_cpu.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/stop_and_free_the_vmm.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/stop_vmm.c ${HEADERS})
hypervisor_target_source(bareflank_efi_loader ../src/stop_vmm_per_cpu.c ${HEADERS})

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
	hypervisor_target_source(bareflank_efi_loader src/x64/arch_init.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/arch_locate_protocols.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/arch_num_online_cpus.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/arch_work_on_cpu.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/demote.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/esr_default.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/esr_df.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/esr_gpf.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/esr_nmi.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/esr_pf.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/flush_cache.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/intrinsic_cpuid.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/intrinsic_inb.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/intrinsic_lcr0.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/intrinsic_lcr4.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/intrinsic_lgdt.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/intrinsic_ltr.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/intrinsic_outb.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/intrinsic_rdmsr.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/intrinsic_scr0.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/intrinsic_scr4.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/intrinsic_scs.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/intrinsic_sds.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/intrinsic_ses.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/intrinsic_sfs.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/intrinsic_sgdt.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/intrinsic_sgs.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/intrinsic_sidt.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/intrinsic_sldtr.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/intrinsic_sss.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/intrinsic_str.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/intrinsic_wrmsr.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/memops.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/promote.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/serial_write_c.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/serial_write_hex.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/x64/setup_tss.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/x64/alloc_and_copy_mk_code_aliases.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/x64/alloc_and_copy_mk_state.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/x64/alloc_and_copy_root_vp_state.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/x64/alloc_mk_root_page_table.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/x64/alloc_pdpt.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/x64/alloc_pdt.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/x64/alloc_pt.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/x64/dump_mk_code_aliases.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/x64/dump_mk_state.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/x64/dump_root_vp_state.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/x64/free_mk_code_aliases.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/x64/free_mk_root_page_table.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/x64/free_mk_state.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/x64/free_pdpt.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/x64/free_pdt.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/x64/free_pml4t.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/x64/free_root_vp_state.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/x64/get_gdt_descriptor_attrib.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/x64/get_gdt_descriptor_base.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/x64/get_gdt_descriptor_limit.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/x64/map_4k_page.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/x64/map_mk_code_aliases.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/x64/map_mk_state.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/x64/map_root_vp_state.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/x64/send_command_report_off.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/x64/send_command_report_on.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/x64/send_command_stop.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/x64/serial_init.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/x64/set_gdt_descriptor.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/x64/set_idt_descriptor.c ${HEADERS})

	if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
		hypervisor_target_source(bareflank_efi_loader src/x64/amd/disable_interrupts.S ${HEADERS})
		hypervisor_target_source(bareflank_efi_loader src/x64/amd/enable_interrupts.S ${HEADERS})
		hypervisor_target_source(bareflank_efi_loader src/x64/amd/setup_cr0.c ${HEADERS})
		hypervisor_target_source(bareflank_efi_loader src/x64/amd/setup_cr4.c ${HEADERS})
		hypervisor_target_source(bareflank_efi_loader ../src/x64/amd/check_cpu_configuration.c ${HEADERS})
		hypervisor_target_source(bareflank_efi_loader ../src/x64/amd/disable_hve.c ${HEADERS})
		hypervisor_target_source(bareflank_efi_loader ../src/x64/amd/enable_hve.c ${HEADERS})
	endif()

	if(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
		hypervisor_target_source(bareflank_efi_loader src/x64/intel/disable_interrupts.S ${HEADERS})
		hypervisor_target_source(bareflank_efi_loader src/x64/intel/enable_interrupts.S ${HEADERS})
		hypervisor_target_source(bareflank_efi_loader src/x64/intel/intrinsic_vmxoff.S ${HEADERS})
		hypervisor_target_source(bareflank_efi_loader src/x64/intel/intrinsic_vmxon.S ${HEADERS})
		hypervisor_target_source(bareflank_efi_loader src/x64/intel/setup_cr0.c ${HEADERS})
		hypervisor_target_source(bareflank_efi_loader src/x64/intel/setup_cr4.c ${HEADERS})
		hypervisor_target_source(bareflank_efi_loader ../src/x64/intel/check_cpu_configuration.c ${HEADERS})
		hypervisor_target_source(bareflank_efi_loader ../src/x64/intel/disable_hve.c ${HEADERS})
		hypervisor_target_source(bareflank_efi_loader ../src/x64/intel/enable_hve.c ${HEADERS})
	endif()
endif()

if(HYPERVISOR_TARGET_ARCH STREQUAL "aarch64")
	hypervisor_target_source(bareflank_efi_loader src/arm/aarch64/arch_init.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/arm/aarch64/arch_locate_protocols.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/arm/aarch64/arch_num_online_cpus.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/arm/aarch64/arch_work_on_cpu.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/arm/aarch64/demote.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/arm/aarch64/esr.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/arm/aarch64/exception_vectors.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/arm/aarch64/flush_cache.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/arm/aarch64/memcpy.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/arm/aarch64/memset.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/arm/aarch64/promote.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/arm/aarch64/read_currentel.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/arm/aarch64/read_daif.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/arm/aarch64/read_hcr_el2.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/arm/aarch64/read_mair_el2.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/arm/aarch64/read_sctlr_el2.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/arm/aarch64/read_spsel.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/arm/aarch64/read_tcr_el2.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/arm/aarch64/read_ttbr0_el2.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/arm/aarch64/read_vbar_el2.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/arm/aarch64/serial_write_c.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader src/arm/aarch64/serial_write_hex.S ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/arm/aarch64/alloc_and_copy_mk_code_aliases.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/arm/aarch64/alloc_and_copy_mk_state.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/arm/aarch64/alloc_and_copy_root_vp_state.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/arm/aarch64/alloc_l1t.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/arm/aarch64/alloc_l2t.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/arm/aarch64/alloc_l3t.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/arm/aarch64/alloc_mk_root_page_table.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/arm/aarch64/check_cpu_configuration.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/arm/aarch64/dump_mk_code_aliases.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/arm/aarch64/dump_mk_state.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/arm/aarch64/dump_root_vp_state.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/arm/aarch64/free_l0t.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/arm/aarch64/free_l1t.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/arm/aarch64/free_l2t.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/arm/aarch64/free_mk_code_aliases.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/arm/aarch64/free_mk_root_page_table.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/arm/aarch64/free_mk_state.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/arm/aarch64/free_root_vp_state.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/arm/aarch64/map_4k_page.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/arm/aarch64/map_mk_code_aliases.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/arm/aarch64/map_mk_state.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/arm/aarch64/map_root_vp_state.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/arm/aarch64/send_command_report_off.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/arm/aarch64/send_command_report_on.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/arm/aarch64/send_command_stop.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/arm/aarch64/serial_init.c ${HEADERS})
	hypervisor_target_source(bareflank_efi_loader ../src/arm/aarch64/serial_write.c ${HEADERS})
endif()

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(TARGETS bareflank_efi_loader DESTINATION bin)
