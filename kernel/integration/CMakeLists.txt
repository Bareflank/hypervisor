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

include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/function/hypervisor_add_integration.cmake)

list(APPEND HEADERS
    ${CMAKE_CURRENT_LIST_DIR}/support/integration_utils.hpp
)

hypervisor_add_integration(bf_callback_op_register_bootstrap HEADERS)
hypervisor_add_integration(bf_callback_op_register_fail HEADERS)
hypervisor_add_integration(bf_callback_op_register_vmexit HEADERS)
hypervisor_add_integration(bf_debug_op_dump_ext HEADERS)
hypervisor_add_integration(bf_debug_op_dump_huge_pool HEADERS)
hypervisor_add_integration(bf_debug_op_dump_page_pool HEADERS)
hypervisor_add_integration(bf_debug_op_dump_vm HEADERS)
hypervisor_add_integration(bf_debug_op_dump_vmexit_log HEADERS)
hypervisor_add_integration(bf_debug_op_dump_vp HEADERS)
hypervisor_add_integration(bf_debug_op_dump_vs HEADERS)
hypervisor_add_integration(bf_debug_op_out HEADERS)
hypervisor_add_integration(bf_debug_op_write_c HEADERS)
hypervisor_add_integration(bf_debug_op_write_str HEADERS)
hypervisor_add_integration(bf_handle_op_close_handle HEADERS)
hypervisor_add_integration(bf_handle_op_open_handle HEADERS)
hypervisor_add_integration(bf_intrinsic_op_rdmsr HEADERS)
hypervisor_add_integration(bf_intrinsic_op_wrmsr HEADERS)
hypervisor_add_integration(bf_mem_op_alloc_huge HEADERS)
hypervisor_add_integration(bf_mem_op_alloc_page HEADERS)
hypervisor_add_integration(bf_vm_op_create_vm HEADERS)
hypervisor_add_integration(bf_vm_op_destroy_vm HEADERS)
hypervisor_add_integration(bf_vm_op_map_direct HEADERS)
hypervisor_add_integration(bf_vm_op_tlb_flush HEADERS)
hypervisor_add_integration(bf_vm_op_unmap_direct HEADERS)
hypervisor_add_integration(bf_vp_op_create_vp HEADERS)
hypervisor_add_integration(bf_vp_op_destroy_vp HEADERS)
hypervisor_add_integration(bf_vs_op_create_vs HEADERS)
hypervisor_add_integration(bf_vs_op_destroy_vs HEADERS)
hypervisor_add_integration(bf_vs_op_advance_ip_and_run_current HEADERS)
hypervisor_add_integration(bf_vs_op_advance_ip_and_run HEADERS)
hypervisor_add_integration(bf_vs_op_advance_ip_and_set_active HEADERS)
hypervisor_add_integration(bf_vs_op_clear HEADERS)
hypervisor_add_integration(bf_vs_op_init_as_root HEADERS)
hypervisor_add_integration(bf_vs_op_migrate HEADERS)
hypervisor_add_integration(bf_vs_op_promote HEADERS)
hypervisor_add_integration(bf_vs_op_read HEADERS)
hypervisor_add_integration(bf_vs_op_run_current HEADERS)
hypervisor_add_integration(bf_vs_op_run HEADERS)
hypervisor_add_integration(bf_vs_op_set_active HEADERS)
hypervisor_add_integration(bf_vs_op_tlb_flush HEADERS)
hypervisor_add_integration(bf_vs_op_write HEADERS)
hypervisor_add_integration(fast_fail_exit_from_bootstrap_with_no_syscall HEADERS)
hypervisor_add_integration(fast_fail_exit_from_bootstrap_with_segfault HEADERS)
hypervisor_add_integration(fast_fail_exit_from_bootstrap_with_wait HEADERS)
hypervisor_add_integration(fast_fail_exit_from_bootstrap HEADERS)
hypervisor_add_integration(fast_fail_exit_from_fail_with_no_syscall HEADERS)
hypervisor_add_integration(fast_fail_exit_from_fail_with_segfault HEADERS)
hypervisor_add_integration(fast_fail_exit_from_fail_with_wait HEADERS)
hypervisor_add_integration(fast_fail_exit_from_fail HEADERS)
hypervisor_add_integration(fast_fail_exit_from_main_with_no_syscall HEADERS)
hypervisor_add_integration(fast_fail_exit_from_main_with_segfault HEADERS)
hypervisor_add_integration(fast_fail_exit_from_main HEADERS)
hypervisor_add_integration(fast_fail_exit_from_vmexit_with_no_syscall HEADERS)
hypervisor_add_integration(fast_fail_exit_from_vmexit_with_segfault HEADERS)
hypervisor_add_integration(fast_fail_exit_from_vmexit_with_wait HEADERS)
hypervisor_add_integration(fast_fail_exit_from_vmexit HEADERS)
hypervisor_add_integration(fast_fail_recover_from_assert HEADERS)
hypervisor_add_integration(fast_fail_recover_from_page_fault HEADERS)
hypervisor_add_integration(fast_fail_wait_no_bootstrap HEADERS)
hypervisor_add_integration(fast_fail_wait_no_fail HEADERS)
hypervisor_add_integration(fast_fail_wait_no_vmexit HEADERS)
