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
    ${CMAKE_SOURCE_DIR}/lib/include
    ${CMAKE_SOURCE_DIR}/lib/mocks
    ${CMAKE_SOURCE_DIR}/loader/include/interface
    ${CMAKE_SOURCE_DIR}/syscall/include
    ${CMAKE_SOURCE_DIR}/syscall/mocks
    ${CMAKE_CURRENT_LIST_DIR}/include
    ${CMAKE_CURRENT_LIST_DIR}/src
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
    ${CMAKE_SOURCE_DIR}/lib/include/x64
    ${CMAKE_SOURCE_DIR}/lib/mocks/x64
    ${CMAKE_SOURCE_DIR}/loader/include/interface/x64
    ${CMAKE_SOURCE_DIR}/syscall/include/x64
    ${CMAKE_SOURCE_DIR}/syscall/mocks/x64
    ${CMAKE_CURRENT_LIST_DIR}/include/x64
    ${CMAKE_CURRENT_LIST_DIR}/src/x64
    ${SYSTEM_INCLUDES}
)

list(APPEND AMD_INCLUDES
    ${CMAKE_CURRENT_LIST_DIR}/../include/x64/amd
    ${CMAKE_CURRENT_LIST_DIR}/../mocks/x64/amd
    ${X64_INCLUDES}
)

list(APPEND AMD_SYSTEM_INCLUDES
    ${CMAKE_SOURCE_DIR}/lib/include/x64/amd
    ${CMAKE_SOURCE_DIR}/lib/mocks/x64/amd
    ${CMAKE_SOURCE_DIR}/loader/include/interface/x64/amd
    ${CMAKE_SOURCE_DIR}/syscall/include/x64/amd
    ${CMAKE_SOURCE_DIR}/syscall/mocks/x64/amd
    ${CMAKE_CURRENT_LIST_DIR}/include/x64/amd
    ${CMAKE_CURRENT_LIST_DIR}/src/x64/amd
    ${X64_SYSTEM_INCLUDES}
)

list(APPEND INTEL_INCLUDES
    ${CMAKE_CURRENT_LIST_DIR}/../include/x64/intel
    ${CMAKE_CURRENT_LIST_DIR}/../mocks/x64/intel
    ${X64_INCLUDES}
)

list(APPEND INTEL_SYSTEM_INCLUDES
    ${CMAKE_SOURCE_DIR}/lib/include/x64/intel
    ${CMAKE_SOURCE_DIR}/lib/mocks/x64/intel
    ${CMAKE_SOURCE_DIR}/loader/include/interface/x64/intel
    ${CMAKE_SOURCE_DIR}/syscall/include/x64/intel
    ${CMAKE_SOURCE_DIR}/syscall/mocks/x64/intel
    ${CMAKE_CURRENT_LIST_DIR}/include/x64/intel
    ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel
    ${X64_SYSTEM_INCLUDES}
)

# ------------------------------------------------------------------------------
# Definitions
# ------------------------------------------------------------------------------

list(APPEND COMMON_DEFINES
   HYPERVISOR_PAGE_SIZE=0x1000_umx
   HYPERVISOR_PAGE_SHIFT=12_umx
   HYPERVISOR_SERIAL_PORT=0x03F8_umx
   HYPERVISOR_DEBUG_RING_SIZE=0x10
   HYPERVISOR_VMEXIT_LOG_SIZE=2_umx
   HYPERVISOR_MAX_ELF_FILE_SIZE=0x800000_umx
   HYPERVISOR_MAX_SEGMENTS=3_umx
   HYPERVISOR_MAX_EXTENSIONS=2_umx
   HYPERVISOR_MAX_PPS=2_umx
   HYPERVISOR_MAX_VMS=2_umx
   HYPERVISOR_MAX_VPS=2_umx
   HYPERVISOR_MAX_VSS=2_umx
   HYPERVISOR_MAX_HUGE_ALLOCS=2_umx
   HYPERVISOR_MK_DIRECT_MAP_ADDR=0x0000400000000000_umx
   HYPERVISOR_MK_DIRECT_MAP_SIZE=0x0000200000000000_umx
   HYPERVISOR_MK_STACK_ADDR=0x0000008000000000_umx
   HYPERVISOR_MK_STACK_SIZE=0x8000_umx
   HYPERVISOR_MK_CODE_ADDR=0x0000028000000000_umx
   HYPERVISOR_MK_CODE_SIZE=0x800000_umx
   HYPERVISOR_MK_PAGE_POOL_ADDR=0x0000400000000000_umx
   HYPERVISOR_MK_PAGE_POOL_SIZE=0x8000000_umx
   HYPERVISOR_MK_HUGE_POOL_ADDR=0x0000400000000000_umx
   HYPERVISOR_MK_HUGE_POOL_SIZE=0x20000_umx
   HYPERVISOR_EXT_DIRECT_MAP_ADDR=0x0000600000000000_umx
   HYPERVISOR_EXT_DIRECT_MAP_SIZE=0x0000200000000000_umx
   HYPERVISOR_EXT_STACK_ADDR=0x0000308000000000_umx
   HYPERVISOR_EXT_STACK_SIZE=0x8000_umx
   HYPERVISOR_EXT_FAIL_STACK_ADDR=0x0000318000000000_umx
   HYPERVISOR_EXT_FAIL_STACK_SIZE=0x8000_umx
   HYPERVISOR_EXT_CODE_ADDR=0x0000328000000000_umx
   HYPERVISOR_EXT_CODE_SIZE=0x800000_umx
   HYPERVISOR_EXT_TLS_ADDR=0x0000338000000000_umx
   HYPERVISOR_EXT_TLS_SIZE=0x2000_umx
   HYPERVISOR_EXT_PAGE_POOL_ADDR=0x0000200000000000_umx
   HYPERVISOR_EXT_PAGE_POOL_SIZE=0x8000000_umx
   HYPERVISOR_EXT_HUGE_POOL_ADDR=0x0000200000000000_umx
   HYPERVISOR_EXT_HUGE_POOL_SIZE=0x20000_umx
)

list(APPEND X64_DEFINES
    ${COMMON_DEFINES}
)

list(APPEND AMD_DEFINES
    ${X64_DEFINES}
)

list(APPEND INTEL_DEFINES
    ${X64_DEFINES}
)

# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------

add_subdirectory(mocks/debug_ring_write)
add_subdirectory(mocks/dispatch_esr)
add_subdirectory(mocks/dispatch_syscall)
add_subdirectory(mocks/dispatch_syscall_bf_callback_op)
add_subdirectory(mocks/dispatch_syscall_bf_control_op)
add_subdirectory(mocks/dispatch_syscall_bf_debug_op)
add_subdirectory(mocks/dispatch_syscall_bf_handle_op)
add_subdirectory(mocks/dispatch_syscall_bf_intrinsic_op)
add_subdirectory(mocks/dispatch_syscall_bf_mem_op)
add_subdirectory(mocks/dispatch_syscall_bf_vm_op)
add_subdirectory(mocks/dispatch_syscall_bf_vp_op)
add_subdirectory(mocks/dispatch_syscall_bf_vs_op)
add_subdirectory(mocks/ext_pool_t)
add_subdirectory(mocks/ext_t)
add_subdirectory(mocks/huge_pool_t)
add_subdirectory(mocks/intrinsic_t)
add_subdirectory(mocks/mk_main_t)
add_subdirectory(mocks/serial_write)
add_subdirectory(mocks/vm_pool_t)
add_subdirectory(mocks/vm_t)
add_subdirectory(mocks/vmexit_log_t)
add_subdirectory(mocks/vmexit_loop)
add_subdirectory(mocks/vp_pool_t)
add_subdirectory(mocks/vp_t)
add_subdirectory(mocks/vs_pool_t)
add_subdirectory(mocks/vs_t)
add_subdirectory(mocks/x64/dispatch_esr_nmi)
add_subdirectory(mocks/x64/amd/intrinsic_t)
add_subdirectory(mocks/x64/intel/intrinsic_t)

add_subdirectory(src/debug_ring_write)
add_subdirectory(src/dispatch_syscall)
add_subdirectory(src/dispatch_syscall_bf_callback_op)
add_subdirectory(src/dispatch_syscall_bf_control_op)
add_subdirectory(src/dispatch_syscall_bf_debug_op)
add_subdirectory(src/dispatch_syscall_bf_handle_op)
add_subdirectory(src/dispatch_syscall_bf_mem_op)
add_subdirectory(src/dispatch_syscall_bf_vm_op)
add_subdirectory(src/dispatch_syscall_bf_vp_op)
add_subdirectory(src/dispatch_syscall_bf_vs_op)
add_subdirectory(src/ext_pool_t)
add_subdirectory(src/ext_t)
add_subdirectory(src/huge_pool_t)
add_subdirectory(src/mk_main_t)
add_subdirectory(src/serial_write)
add_subdirectory(src/vm_pool_t)
add_subdirectory(src/vm_t)
add_subdirectory(src/vmexit_loop)
add_subdirectory(src/vp_pool_t)
add_subdirectory(src/vp_t)
add_subdirectory(src/vs_pool_t)
add_subdirectory(src/x64/dispatch_esr)
add_subdirectory(src/x64/dispatch_syscall_bf_intrinsic_op)
add_subdirectory(src/x64/vmexit_log_t)
add_subdirectory(src/x64/amd/dispatch_esr_nmi)
add_subdirectory(src/x64/amd/intrinsic_t)
add_subdirectory(src/x64/amd/vs_t)
add_subdirectory(src/x64/intel/dispatch_esr_nmi)
add_subdirectory(src/x64/intel/intrinsic_t)
add_subdirectory(src/x64/intel/vs_t)

