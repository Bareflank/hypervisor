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
    ${CMAKE_CURRENT_LIST_DIR}/../include
    ${CMAKE_CURRENT_LIST_DIR}/../mocks
)

list(APPEND SYSTEM_INCLUDES
    ${CMAKE_SOURCE_DIR}/syscall/include/cpp
    ${CMAKE_SOURCE_DIR}/syscall/mocks/cpp
    ${CMAKE_SOURCE_DIR}/loader/include/interface/cpp
)

list(APPEND COMMON_INCLUDES
    ${INCLUDES}
)

list(APPEND COMMON_SYSTEM_INCLUDES
    ${SYSTEM_INCLUDES}
)

list(APPEND X64_INCLUDES
    ${CMAKE_CURRENT_LIST_DIR}/../include/x64
    ${CMAKE_CURRENT_LIST_DIR}/../mocks/x64
    ${INCLUDES}
)

list(APPEND X64_SYSTEM_INCLUDES
    ${CMAKE_SOURCE_DIR}/syscall/include/cpp/x64
    ${CMAKE_SOURCE_DIR}/syscall/mocks/cpp/x64
    ${CMAKE_SOURCE_DIR}/loader/include/interface/cpp/x64
    ${SYSTEM_INCLUDES}
)

list(APPEND AMD_INCLUDES
    ${CMAKE_CURRENT_LIST_DIR}/../include/x64/amd
    ${CMAKE_CURRENT_LIST_DIR}/../mocks/x64/amd
    ${X64_INCLUDES}
)

list(APPEND AMD_SYSTEM_INCLUDES
    ${CMAKE_SOURCE_DIR}/syscall/include/cpp/x64/amd
    ${CMAKE_SOURCE_DIR}/syscall/mocks/cpp/x64/amd
    ${CMAKE_SOURCE_DIR}/loader/include/interface/cpp/x64/amd
    ${X64_SYSTEM_INCLUDES}
)

list(APPEND INTEL_INCLUDES
    ${CMAKE_CURRENT_LIST_DIR}/../include/x64/intel
    ${CMAKE_CURRENT_LIST_DIR}/../mocks/x64/intel
    ${X64_INCLUDES}
)

list(APPEND INTEL_SYSTEM_INCLUDES
    ${CMAKE_SOURCE_DIR}/syscall/include/cpp/x64/intel
    ${CMAKE_SOURCE_DIR}/syscall/mocks/cpp/x64/intel
    ${CMAKE_SOURCE_DIR}/loader/include/interface/cpp/x64/intel
    ${X64_SYSTEM_INCLUDES}
)

list(APPEND AARCH64_INCLUDES
    ${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64
    ${CMAKE_CURRENT_LIST_DIR}/../mocks/arm/aarch64
    ${INCLUDES}
)

list(APPEND AARCH64_SYSTEM_INCLUDES
    ${CMAKE_SOURCE_DIR}/syscall/include/cpp/arm/aarch64
    ${CMAKE_SOURCE_DIR}/syscall/mocks/cpp/arm/aarch64
    ${CMAKE_SOURCE_DIR}/loader/include/interface/cpp/arm/aarch64
    ${SYSTEM_INCLUDES}
)

# ------------------------------------------------------------------------------
# Definitions
# ------------------------------------------------------------------------------

list(APPEND DEFINES
    HYPERVISOR_DEBUG_RING_SIZE=0x7FF0
    HYPERVISOR_PAGE_SIZE=0x1000_umax
    HYPERVISOR_MAX_VMS=2_umax
    HYPERVISOR_MAX_VPS=2_umax
    HYPERVISOR_MAX_VPSS=2_umax
    HYPERVISOR_MK_PAGE_POOL_ADDR=0x1000_umax
    HYPERVISOR_MK_HUGE_POOL_ADDR=0x1000_umax
)

list(APPEND COMMON_DEFINES
    ${DEFINES}
)

list(APPEND X64_DEFINES
    ${DEFINES}
)

list(APPEND AMD_DEFINES
    ${X64_DEFINES}
)

list(APPEND INTEL_DEFINES
    ${X64_DEFINES}
)

list(APPEND AARCH64_DEFINES
    ${DEFINES}
)

# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------

# add_subdirectory(bfelf/elf64_ehdr_t)
# add_subdirectory(bfelf/elf64_phdr_t)
# add_subdirectory(cstdio)
# add_subdirectory(details/print_thread_id)
# add_subdirectory(details/putc_stderr)
# add_subdirectory(details/putc_stdout)
# add_subdirectory(details/puts_stderr)
# add_subdirectory(details/puts_stdout)
# add_subdirectory(debug_ring_write)
# add_subdirectory(dispatch_esr_page_fault)
# add_subdirectory(dispatch_syscall)
# add_subdirectory(dispatch_syscall_callback_op)
# add_subdirectory(dispatch_syscall_callback_op_failure)
# add_subdirectory(dispatch_syscall_control_op)
# add_subdirectory(dispatch_syscall_control_op_failure)
# add_subdirectory(dispatch_syscall_debug_op)
# add_subdirectory(dispatch_syscall_debug_op_failure)
# add_subdirectory(dispatch_syscall_handle_op)
# add_subdirectory(dispatch_syscall_handle_op_failure)
# add_subdirectory(dispatch_syscall_mem_op)
# add_subdirectory(dispatch_syscall_mem_op_failure)
# add_subdirectory(dispatch_syscall_vm_op)
# add_subdirectory(dispatch_syscall_vm_op_failure)
# add_subdirectory(dispatch_syscall_vp_op)
# add_subdirectory(dispatch_syscall_vp_op_failure)
# add_subdirectory(dispatch_syscall_vps_op)
# add_subdirectory(dispatch_syscall_vps_op_failure)
# add_subdirectory(ext_pool_t)
# add_subdirectory(ext_t)
# add_subdirectory(fast_fail)
add_subdirectory(huge_pool_t)
# add_subdirectory(lock_guard_t)
# add_subdirectory(mk_main)
# add_subdirectory(msg_halt)
# add_subdirectory(msg_stack_chk_fail)
add_subdirectory(page_pool_t)
# add_subdirectory(serial_write)
# add_subdirectory(spinlock_t)
# add_subdirectory(vm_pool_t)
# add_subdirectory(vm_t)
# add_subdirectory(vmexit_loop)
# add_subdirectory(vp_pool_t)
# add_subdirectory(vp_t)
# add_subdirectory(vps_pool_t)

# add_subdirectory(x64/dispatch_esr)
# add_subdirectory(x64/root_page_table_t)
# add_subdirectory(x64/vmexit_log_t)

# add_subdirectory(x64/amd/dispatch_esr_nmi)
# add_subdirectory(x64/amd/dispatch_syscall_intrinsic_op)
# add_subdirectory(x64/amd/intrinsic_t)
# add_subdirectory(x64/amd/vps_t)

# add_subdirectory(x64/intel/dispatch_esr_nmi)
# add_subdirectory(x64/intel/dispatch_syscall_intrinsic_op)
# add_subdirectory(x64/intel/intrinsic_t)
# add_subdirectory(x64/intel/vps_t)

# add_subdirectory(arm/aarch64/dispatch_esr)
# add_subdirectory(arm/aarch64/dispatch_syscall_intrinsic_op)
# add_subdirectory(arm/aarch64/intrinsic_t)
# add_subdirectory(arm/aarch64/root_page_table_t)
# add_subdirectory(arm/aarch64/vmexit_log_t)
# add_subdirectory(arm/aarch64/vps_t)
