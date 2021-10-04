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

include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/function/hypervisor_add_integration_target.cmake)

hypervisor_add_integration_target(bf_callback_op_register_bootstrap)
hypervisor_add_integration_target(bf_callback_op_register_fail)
hypervisor_add_integration_target(bf_callback_op_register_vmexit)
hypervisor_add_integration_target(bf_handle_op_close_handle)
hypervisor_add_integration_target(bf_handle_op_open_handle)
hypervisor_add_integration_target(bf_vm_op_create_vm)
hypervisor_add_integration_target(bf_vm_op_destroy_vm)
hypervisor_add_integration_target(bf_vm_op_map_direct)
hypervisor_add_integration_target(bf_vm_op_unmap_direct)
hypervisor_add_integration_target(bf_vm_op_unmap_direct_broadcast)
hypervisor_add_integration_target(bf_vp_op_create_vp)
hypervisor_add_integration_target(bf_vp_op_destroy_vp)
hypervisor_add_integration_target(bf_vs_op_create_vs)
hypervisor_add_integration_target(bf_vs_op_destroy_vs)
hypervisor_add_integration_target(fast_fail_exit_from_bootstrap_with_no_syscall)
hypervisor_add_integration_target(fast_fail_exit_from_bootstrap_with_segfault)
hypervisor_add_integration_target(fast_fail_exit_from_bootstrap_with_wait)
hypervisor_add_integration_target(fast_fail_exit_from_bootstrap)
hypervisor_add_integration_target(fast_fail_exit_from_fail_with_no_syscall)
hypervisor_add_integration_target(fast_fail_exit_from_fail_with_segfault)
hypervisor_add_integration_target(fast_fail_exit_from_fail_with_wait)
hypervisor_add_integration_target(fast_fail_exit_from_fail)
hypervisor_add_integration_target(fast_fail_exit_from_main_with_no_syscall)
hypervisor_add_integration_target(fast_fail_exit_from_main_with_segfault)
hypervisor_add_integration_target(fast_fail_exit_from_main)
hypervisor_add_integration_target(fast_fail_exit_from_vmexit_with_no_syscall)
hypervisor_add_integration_target(fast_fail_exit_from_vmexit_with_segfault)
hypervisor_add_integration_target(fast_fail_exit_from_vmexit_with_wait)
hypervisor_add_integration_target(fast_fail_exit_from_vmexit)
hypervisor_add_integration_target(fast_fail_from_fail_handler)
hypervisor_add_integration_target(fast_fail_recover_from_assert)
hypervisor_add_integration_target(fast_fail_recover_from_page_fault)
hypervisor_add_integration_target(fast_fail_wait_no_bootstrap)
hypervisor_add_integration_target(fast_fail_wait_no_fail)
hypervisor_add_integration_target(fast_fail_wait_no_vmexit)
