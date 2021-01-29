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

if (NOT CMAKE_PROJECT_NAME STREQUAL "hypervisor_microkernel")
    add_library(syscall)

    target_include_directories(syscall PUBLIC
        include/cpp/
    )

    target_sources(syscall PRIVATE
        src/x64/bf_callback_op_register_bootstrap_impl.S
        src/x64/bf_callback_op_register_fail_impl.S
        src/x64/bf_callback_op_register_vmexit_impl.S
        src/x64/bf_callback_op_wait_impl.S
        src/x64/bf_control_op_exit_impl.S
        src/x64/bf_debug_op_dump_vm_impl.S
        src/x64/bf_debug_op_dump_vmexit_log_impl.S
        src/x64/bf_debug_op_dump_vp_impl.S
        src/x64/bf_debug_op_dump_vps_impl.S
        src/x64/bf_debug_op_out_impl.S
        src/x64/bf_debug_op_write_c_impl.S
        src/x64/bf_debug_op_write_str_impl.S
        src/x64/bf_handle_op_close_handle_impl.S
        src/x64/bf_handle_op_open_handle_impl.S
        src/x64/bf_intrinsic_op_read_msr_impl.S
        src/x64/bf_intrinsic_op_write_msr_impl.S
        src/x64/bf_mem_op_alloc_page_impl.S
        src/x64/bf_mem_op_virt_to_phys_impl.S
        src/x64/bf_tls_rax_impl.S
        src/x64/bf_tls_rbx_impl.S
        src/x64/bf_tls_rcx_impl.S
        src/x64/bf_tls_rdx_impl.S
        src/x64/bf_tls_rbp_impl.S
        src/x64/bf_tls_rsi_impl.S
        src/x64/bf_tls_rdi_impl.S
        src/x64/bf_tls_r8_impl.S
        src/x64/bf_tls_r9_impl.S
        src/x64/bf_tls_r10_impl.S
        src/x64/bf_tls_r11_impl.S
        src/x64/bf_tls_r12_impl.S
        src/x64/bf_tls_r13_impl.S
        src/x64/bf_tls_r14_impl.S
        src/x64/bf_tls_r15_impl.S
        src/x64/bf_tls_set_rax_impl.S
        src/x64/bf_tls_set_rbx_impl.S
        src/x64/bf_tls_set_rcx_impl.S
        src/x64/bf_tls_set_rdx_impl.S
        src/x64/bf_tls_set_rbp_impl.S
        src/x64/bf_tls_set_rsi_impl.S
        src/x64/bf_tls_set_rdi_impl.S
        src/x64/bf_tls_set_r8_impl.S
        src/x64/bf_tls_set_r9_impl.S
        src/x64/bf_tls_set_r10_impl.S
        src/x64/bf_tls_set_r11_impl.S
        src/x64/bf_tls_set_r12_impl.S
        src/x64/bf_tls_set_r13_impl.S
        src/x64/bf_tls_set_r14_impl.S
        src/x64/bf_tls_set_r15_impl.S
        src/x64/bf_tls_thread_id_impl.S
        src/x64/bf_vm_op_create_vm_impl.S
        src/x64/bf_vm_op_destroy_vm_impl.S
        src/x64/bf_vp_op_create_vp_impl.S
        src/x64/bf_vp_op_destroy_vp_impl.S
        src/x64/bf_vps_op_advance_ip_and_run_current_impl.S
        src/x64/bf_vps_op_advance_ip_impl.S
        src/x64/bf_vps_op_create_vps_impl.S
        src/x64/bf_vps_op_destroy_vps_impl.S
        src/x64/bf_vps_op_init_as_root_impl.S
        src/x64/bf_vps_op_promote_impl.S
        src/x64/bf_vps_op_read_reg_impl.S
        src/x64/bf_vps_op_read8_impl.S
        src/x64/bf_vps_op_read16_impl.S
        src/x64/bf_vps_op_read32_impl.S
        src/x64/bf_vps_op_read64_impl.S
        src/x64/bf_vps_op_run_impl.S
        src/x64/bf_vps_op_run_current_impl.S
        src/x64/bf_vps_op_write_reg_impl.S
        src/x64/bf_vps_op_write8_impl.S
        src/x64/bf_vps_op_write16_impl.S
        src/x64/bf_vps_op_write32_impl.S
        src/x64/bf_vps_op_write64_impl.S
    )

    target_link_libraries(syscall PUBLIC
        bsl
    )
else()
    add_library(syscall INTERFACE)

    target_include_directories(syscall INTERFACE
        include/cpp/
    )

    target_link_libraries(syscall INTERFACE
        bsl
    )
endif()
