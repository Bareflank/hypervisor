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

target_include_directories(syscall PUBLIC
    include/cpp
    src/cpp
)

# ------------------------------------------------------------------------------
# Headers
# ------------------------------------------------------------------------------

list(APPEND HEADERS
    ${CMAKE_CURRENT_LIST_DIR}/include/cpp/bf_constants.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/cpp/bf_reg_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/cpp/bf_types.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/cpp/bf_control_ops.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/cpp/bf_debug_ops.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/cpp/bf_syscall_impl.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/cpp/bf_syscall_t.hpp
)

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
    hypervisor_target_source(syscall src/x64/bf_debug_op_dump_vps_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_debug_op_out_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_debug_op_write_c_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_debug_op_write_str_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_handle_op_close_handle_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_handle_op_open_handle_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_intrinsic_op_invept_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_intrinsic_op_invlpga_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_intrinsic_op_invvpid_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_intrinsic_op_rdmsr_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_intrinsic_op_wrmsr_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_mem_op_alloc_heap_impl.S ${HEADERS})
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
    hypervisor_target_source(syscall src/x64/bf_tls_vpsid_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vm_op_create_vm_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vm_op_destroy_vm_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vp_op_create_vp_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vp_op_destroy_vp_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vp_op_migrate_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vps_op_advance_ip_and_run_current_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vps_op_advance_ip_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vps_op_clear_vps_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vps_op_create_vps_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vps_op_destroy_vps_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vps_op_init_as_root_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vps_op_promote_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vps_op_read_reg_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vps_op_read8_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vps_op_read16_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vps_op_read32_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vps_op_read64_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vps_op_run_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vps_op_run_current_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vps_op_write_reg_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vps_op_write8_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vps_op_write16_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vps_op_write32_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/x64/bf_vps_op_write64_impl.S ${HEADERS})
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
    hypervisor_target_source(syscall src/arm/aarch64/bf_debug_op_dump_vps_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_debug_op_out_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_debug_op_write_c_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_debug_op_write_str_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_handle_op_close_handle_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_handle_op_open_handle_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_intrinsic_op_invept_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_intrinsic_op_invlpga_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_intrinsic_op_invvpid_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_intrinsic_op_rdmsr_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_intrinsic_op_wrmsr_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_mem_op_alloc_heap_impl.S ${HEADERS})
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
    hypervisor_target_source(syscall src/arm/aarch64/bf_tls_vpsid_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vm_op_create_vm_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vm_op_destroy_vm_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vp_op_create_vp_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vp_op_destroy_vp_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vp_op_migrate_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vps_op_advance_ip_and_run_current_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vps_op_advance_ip_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vps_op_clear_vps_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vps_op_create_vps_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vps_op_destroy_vps_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vps_op_init_as_root_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vps_op_promote_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vps_op_read_reg_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vps_op_read8_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vps_op_read16_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vps_op_read32_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vps_op_read64_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vps_op_run_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vps_op_run_current_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vps_op_write_reg_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vps_op_write8_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vps_op_write16_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vps_op_write32_impl.S ${HEADERS})
    hypervisor_target_source(syscall src/arm/aarch64/bf_vps_op_write64_impl.S ${HEADERS})
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
