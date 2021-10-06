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

include(${CMAKE_CURRENT_LIST_DIR}/../cmake/function/hypervisor_target_source.cmake)

add_executable(kernel_bin)

# ------------------------------------------------------------------------------
# Includes
# ------------------------------------------------------------------------------

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
        target_include_directories(kernel_bin PRIVATE
            include/x64/amd
            src/x64/amd
        )
    endif()

    if(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
        target_include_directories(kernel_bin PRIVATE
            include/x64/intel
            src/x64/intel
        )
    endif()

    target_include_directories(kernel_bin PRIVATE
        include/x64
        src/x64
    )
endif()

if(HYPERVISOR_TARGET_ARCH STREQUAL "aarch64")
    target_include_directories(kernel_bin PRIVATE
        include/arm/aarch64
        src/arm/aarch64
    )
endif()

target_include_directories(kernel_bin PRIVATE
    include
    src
)

# ------------------------------------------------------------------------------
# Headers
# ------------------------------------------------------------------------------

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
        list(APPEND HEADERS
            ${CMAKE_CURRENT_LIST_DIR}/include/x64/amd/vmcb_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/amd/dispatch_esr_nmi.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/amd/intrinsic_invlpga.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/amd/intrinsic_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/amd/intrinsic_vmrun.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/amd/vs_t.hpp
        )
    endif()

    if(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
        list(APPEND HEADERS
            ${CMAKE_CURRENT_LIST_DIR}/include/x64/intel/invept_descriptor_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/include/x64/intel/invvpid_descriptor_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/include/x64/intel/vmcs_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/dispatch_esr_nmi.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/intrinsic_invept.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/intrinsic_invvpid.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/intrinsic_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/intrinsic_vmcl.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/intrinsic_vmld.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/intrinsic_vmrd16.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/intrinsic_vmrd32.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/intrinsic_vmrd64.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/intrinsic_vmrun.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/intrinsic_vmwr16.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/intrinsic_vmwr32.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/intrinsic_vmwr64.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/intrinsic_vmwrfunc.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/vs_t.hpp
        )
    endif()

    list(APPEND HEADERS
        ${CMAKE_CURRENT_LIST_DIR}/include/x64/general_purpose_regs_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/include/x64/l0e_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/include/x64/l1e_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/include/x64/l2e_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/include/x64/l3e_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/include/x64/missing_registers_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/include/x64/vmexit_log_pp_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/include/x64/vmexit_log_record_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/dispatch_esr.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/dispatch_syscall_bf_intrinsic_op.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/intrinsic_cr0.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/intrinsic_cr3.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/intrinsic_cr4.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/intrinsic_cs_selector.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/intrinsic_ds_selector.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/intrinsic_es_selector.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/intrinsic_fs_selector.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/intrinsic_gs_selector.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/intrinsic_invlpg.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/intrinsic_rdmsr.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/intrinsic_set_cr3.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/intrinsic_set_tls_reg.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/intrinsic_set_tp.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/intrinsic_ss_selector.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/intrinsic_tls_reg.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/intrinsic_tr_selector.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/intrinsic_wrmsr.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/root_page_table_helpers.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/tls_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/vmexit_log_t.hpp
    )
endif()

list(APPEND HEADERS
    ${CMAKE_CURRENT_LIST_DIR}/include/allocated_status_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/alloc_huge_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/alloc_page_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/bfelf/elf64_ehdr_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/bfelf/elf64_phdr_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/bfelf/elf64_shdr_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/errc_types.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/ext_tcb_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/map_page_flags.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/page_4k_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/page_aligned_bytes_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/bsl/cstdio.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/bsl/cstdlib.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/bsl/details/print_thread_id.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/debug_ring_write.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/call_ext.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_syscall_bf_callback_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_syscall_bf_control_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_syscall_bf_debug_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_syscall_bf_handle_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_syscall_bf_mem_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_syscall_bf_vm_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_syscall_bf_vp_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_syscall_bf_vs_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_syscall_helpers.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_syscall.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/get_current_tls.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/ext_pool_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/ext_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/huge_pool_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/lock_guard_helpers.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/lock_guard_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/mk_main_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/page_pool_helpers.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/page_pool_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/pause.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/promote.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/return_to_mk.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/root_page_table_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/serial_write_c.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/serial_write_hex.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/serial_write.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/spinlock_helpers.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/spinlock_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/vmexit_loop.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/vm_pool_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/vm_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/vp_pool_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/vp_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/vs_pool_t.hpp

    ${CMAKE_CURRENT_LIST_DIR}/../lib/include/basic_allocated_status_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/../lib/include/basic_alloc_huge_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/../lib/include/basic_alloc_page_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/../lib/include/basic_entries_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/../lib/include/basic_entry_status_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/../lib/include/basic_lock_guard_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/../lib/include/basic_map_page_flags.hpp
    ${CMAKE_CURRENT_LIST_DIR}/../lib/include/basic_page_1g_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/../lib/include/basic_page_2m_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/../lib/include/basic_page_4k_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/../lib/include/basic_page_pool_node_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/../lib/include/basic_page_table_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/../lib/include/basic_queue_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/../lib/src/basic_page_pool_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/../lib/src/basic_root_page_table_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/../lib/src/basic_spinlock_t.hpp
)

# ------------------------------------------------------------------------------
# Sources
# ------------------------------------------------------------------------------

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
        hypervisor_target_source(kernel_bin src/x64/amd/intrinsic_invlpga.S ${HEADERS})
        hypervisor_target_source(kernel_bin src/x64/amd/intrinsic_vmrun.S ${HEADERS})
        hypervisor_target_source(kernel_bin src/x64/amd/promote.S ${HEADERS})
    endif()

    if(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
        hypervisor_target_source(kernel_bin src/x64/intel/intrinsic_invept.S ${HEADERS})
        hypervisor_target_source(kernel_bin src/x64/intel/intrinsic_invvpid.S ${HEADERS})
        hypervisor_target_source(kernel_bin src/x64/intel/intrinsic_vmcl.S ${HEADERS})
        hypervisor_target_source(kernel_bin src/x64/intel/intrinsic_vmld.S ${HEADERS})
        hypervisor_target_source(kernel_bin src/x64/intel/intrinsic_vmrd16.S ${HEADERS})
        hypervisor_target_source(kernel_bin src/x64/intel/intrinsic_vmrd32.S ${HEADERS})
        hypervisor_target_source(kernel_bin src/x64/intel/intrinsic_vmrd64.S ${HEADERS})
        hypervisor_target_source(kernel_bin src/x64/intel/intrinsic_vmrun.S ${HEADERS})
        hypervisor_target_source(kernel_bin src/x64/intel/intrinsic_vmwr16.S ${HEADERS})
        hypervisor_target_source(kernel_bin src/x64/intel/intrinsic_vmwr32.S ${HEADERS})
        hypervisor_target_source(kernel_bin src/x64/intel/intrinsic_vmwr64.S ${HEADERS})
        hypervisor_target_source(kernel_bin src/x64/intel/intrinsic_vmwrfunc.S ${HEADERS})
        hypervisor_target_source(kernel_bin src/x64/intel/promote.S ${HEADERS})
    endif()

    hypervisor_target_source(kernel_bin src/x64/call_ext.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/dispatch_esr_entry.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/dispatch_syscall_entry.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/get_current_tls.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/intrinsic_assert.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/intrinsic_cr0.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/intrinsic_cr3.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/intrinsic_cr4.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/intrinsic_cs_selector.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/intrinsic_ds_selector.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/intrinsic_es_selector.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/intrinsic_fs_selector.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/intrinsic_gs_selector.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/intrinsic_halt.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/intrinsic_invlpg.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/intrinsic_rdmsr.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/intrinsic_rdmsr_unsafe.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/intrinsic_set_cr3.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/intrinsic_set_tls_reg.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/intrinsic_set_tp.hpp ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/intrinsic_set_tp.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/intrinsic_ss_selector.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/intrinsic_tls_reg.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/intrinsic_tr_selector.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/intrinsic_wrmsr.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/intrinsic_wrmsr_unsafe.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/mk_main_entry.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/pause.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/return_to_mk.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/serial_write_c.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/serial_write_hex.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/set_esr.S ${HEADERS})
    hypervisor_target_source(kernel_bin src/x64/__stack_chk_fail.S ${HEADERS})
endif()

hypervisor_target_source(kernel_bin src/main.cpp ${HEADERS})
hypervisor_target_source(kernel_bin src/msg_halt.cpp ${HEADERS})
hypervisor_target_source(kernel_bin src/msg_stack_chk_fail.cpp ${HEADERS})

# ------------------------------------------------------------------------------
# Libraries
# ------------------------------------------------------------------------------

target_link_libraries(kernel_bin PRIVATE
    bsl
    loader
    syscall
    hypervisor
    lib
)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL RELEASE OR CMAKE_BUILD_TYPE STREQUAL MINSIZEREL)
    add_custom_command(TARGET kernel_bin POST_BUILD COMMAND ${CMAKE_STRIP} kernel_bin)
endif()

install(TARGETS kernel_bin DESTINATION bin)
