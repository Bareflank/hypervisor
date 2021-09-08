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

add_library(syscall)

# ------------------------------------------------------------------------------
# Includes
# ------------------------------------------------------------------------------

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
        target_include_directories(syscall PUBLIC
            include/x64/amd
            src/x64/amd
        )
    endif()

    if(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
        target_include_directories(syscall PUBLIC
            include/x64/intel
            src/x64/intel
        )
    endif()

    target_include_directories(syscall PUBLIC
        include/x64
        src/x64
    )
endif()

if(HYPERVISOR_TARGET_ARCH STREQUAL "aarch64")
    target_include_directories(syscall PUBLIC
        include/arm/aarch64
        src/arm/aarch64
    )
endif()

target_include_directories(syscall PUBLIC
    include
    src
)

# ------------------------------------------------------------------------------
# Headers
# ------------------------------------------------------------------------------

list(APPEND HEADERS
    ${CMAKE_CURRENT_LIST_DIR}/include/bf_constants.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/bf_types.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/bf_control_ops.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/bf_debug_ops.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/bf_syscall_impl.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/bf_syscall_t.hpp
)

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
        list(APPEND HEADERS
            ${CMAKE_CURRENT_LIST_DIR}/include/x64/amd/bf_reg_t.hpp
        )
    endif()

    if(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
        list(APPEND HEADERS
            ${CMAKE_CURRENT_LIST_DIR}/include/x64/intel/bf_reg_t.hpp
        )
    endif()
endif()

if(HYPERVISOR_TARGET_ARCH STREQUAL "aarch64")
    list(APPEND HEADERS
        ${CMAKE_CURRENT_LIST_DIR}/include/arm/aarch64/bf_reg_t.hpp
    )
endif()

# ------------------------------------------------------------------------------
# Sources
# ------------------------------------------------------------------------------

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    hypervisor_target_source(syscall src/x64/bf_callback_op_register_bootstrap_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_callback_op_register_fail_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_callback_op_register_vmexit_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_control_op_exit_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_control_op_wait_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_debug_op_dump_ext_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_debug_op_dump_huge_pool_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_debug_op_dump_page_pool_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_debug_op_dump_vm_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_debug_op_dump_vmexit_log_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_debug_op_dump_vp_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_debug_op_dump_vs_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_debug_op_out_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_debug_op_write_c_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_debug_op_write_str_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_handle_op_close_handle_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_handle_op_open_handle_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_intrinsic_op_rdmsr_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_intrinsic_op_wrmsr_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_mem_op_alloc_huge_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_mem_op_alloc_page_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_mem_op_free_huge_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_mem_op_free_page_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_extid_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_online_pps_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_ppid_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_rax_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_rbx_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_rcx_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_rdx_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_rbp_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_rsi_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_rdi_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_r8_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_r9_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_r10_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_r11_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_r12_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_r13_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_r14_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_r15_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_set_rax_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_set_rbx_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_set_rcx_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_set_rdx_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_set_rbp_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_set_rsi_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_set_rdi_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_set_r8_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_set_r9_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_set_r10_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_set_r11_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_set_r12_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_set_r13_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_set_r14_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_set_r15_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_thread_id_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_vmid_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_vpid_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_tls_vsid_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vm_op_create_vm_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vm_op_destroy_vm_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vm_op_map_direct_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vm_op_unmap_direct_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vm_op_unmap_direct_broadcast_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vp_op_create_vp_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vp_op_destroy_vp_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vp_op_migrate_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vs_op_advance_ip_and_run_current_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vs_op_advance_ip_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vs_op_clear_vs_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vs_op_create_vs_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vs_op_destroy_vs_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vs_op_init_as_root_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vs_op_promote_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vs_op_read_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vs_op_run_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vs_op_run_current_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vs_op_write_impl.S ${HEADERS})
endif()

if(HYPERVISOR_TARGET_ARCH STREQUAL "aarch64")
    hypervisor_target_source(syscall src/arm/aarch64/bf_callback_op_register_bootstrap_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_callback_op_register_fail_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_callback_op_register_vmexit_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_control_op_exit_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_control_op_wait_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_debug_op_dump_ext_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_debug_op_dump_huge_pool_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_debug_op_dump_page_pool_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_debug_op_dump_vm_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_debug_op_dump_vmexit_log_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_debug_op_dump_vp_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_debug_op_dump_vs_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_debug_op_out_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_debug_op_write_c_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_debug_op_write_str_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_handle_op_close_handle_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_handle_op_open_handle_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_intrinsic_op_rdmsr_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_intrinsic_op_wrmsr_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_mem_op_alloc_huge_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_mem_op_alloc_page_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_mem_op_free_huge_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_mem_op_free_page_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_extid_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_online_pps_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_ppid_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_rax_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_rbx_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_rcx_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_rdx_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_rbp_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_rsi_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_rdi_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_r8_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_r9_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_r10_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_r11_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_r12_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_r13_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_r14_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_r15_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_set_rax_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_set_rbx_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_set_rcx_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_set_rdx_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_set_rbp_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_set_rsi_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_set_rdi_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_set_r8_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_set_r9_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_set_r10_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_set_r11_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_set_r12_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_set_r13_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_set_r14_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_set_r15_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_thread_id_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_vmid_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_vpid_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_vsid_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vm_op_create_vm_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vm_op_destroy_vm_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vm_op_map_direct_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vm_op_unmap_direct_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vm_op_unmap_direct_broadcast_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vp_op_create_vp_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vp_op_destroy_vp_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vp_op_migrate_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vs_op_advance_ip_and_run_current_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vs_op_advance_ip_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vs_op_clear_vs_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vs_op_create_vs_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vs_op_destroy_vs_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vs_op_init_as_root_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vs_op_promote_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vs_op_read_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vs_op_run_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vs_op_run_current_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vs_op_write_impl.S ${HEADERS})
endif()

# ------------------------------------------------------------------------------
# Libraries
# ------------------------------------------------------------------------------

target_link_libraries(syscall PUBLIC
    bsl
    hypervisor
)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(TARGETS syscall DESTINATION lib)
