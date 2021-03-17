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

include(${CMAKE_CURRENT_LIST_DIR}/../cmake/function/hypervisor_add_header_depends.cmake)

add_executable(kernel)

target_include_directories(kernel PRIVATE
    src
)

list(APPEND HEADERS
    ${CMAKE_CURRENT_LIST_DIR}/src/call_ext.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/debug_ring_write.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_syscall_callback_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_syscall_control_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_syscall_debug_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_syscall_handle_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_syscall.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_syscall_mem_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_syscall_vm_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_syscall_vp_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_syscall_vps_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/ext_pool_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/ext_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/fast_fail.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/get_current_tls.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/global_resources.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/huge_pool_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/mk_main.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/page_pool_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/page_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/promote.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/return_to_mk.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/return_to_vmexit_loop.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/vmexit_loop_entry.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/vmexit_loop.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/vm_pool_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/vm_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/vp_pool_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/vps_pool_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/vp_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/bsl/cstdio.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/bsl/details/print_thread_id.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/bsl/details/putc_stderr.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/bsl/details/putc_stdout.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/bsl/details/puts_stderr.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/bsl/details/puts_stdout.hpp
)

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    target_include_directories(kernel PRIVATE
        src/x64
    )

    list(APPEND HEADERS
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/dispatch_esr.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/dispatch_syscall_intrinsic_op.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/pdpt_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/pdt_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/pml4t_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/pt_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/root_page_table_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/serial_write.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/smap_guard_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/tls_t.hpp
    )
endif()

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
    target_include_directories(kernel PRIVATE
        src/x64/amd
    )
    list(APPEND HEADERS
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/amd/dispatch_esr_nmi.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/amd/intrinsic_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/amd/vmcb_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/amd/vps_t.hpp
    )
elseif(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    target_include_directories(kernel PRIVATE
        src/x64/intel
    )
    list(APPEND HEADERS
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/dispatch_esr_nmi.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/intrinsic_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/vmcs_missing_registers_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/vmcs_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/vps_t.hpp
    )
else()
    message(FATAL_ERROR "Unsupported HYPERVISOR_TARGET_ARCH: ${HYPERVISOR_TARGET_ARCH}")
endif()

target_sources(kernel PRIVATE
    src/dispatch_esr_trampoline.cpp
    src/dispatch_syscall_trampoline.cpp
    src/fast_fail_trampoline.cpp
    src/mk_main_trampoline.cpp
    src/msg_halt.cpp
    src/msg_stack_chk_fail.cpp
    src/vmexit_loop_trampoline.cpp
)

hypervisor_add_header_depends(src/dispatch_esr_trampoline.cpp ${HEADERS})
hypervisor_add_header_depends(src/dispatch_syscall_trampoline.cpp ${HEADERS})
hypervisor_add_header_depends(src/fast_fail_trampoline.cpp ${HEADERS})
hypervisor_add_header_depends(src/mk_main_trampoline.cpp ${HEADERS})
hypervisor_add_header_depends(src/msg_halt.cpp ${HEADERS})
hypervisor_add_header_depends(src/msg_stack_chk_fail.cpp ${HEADERS})
hypervisor_add_header_depends(src/vmexit_loop_trampoline.cpp ${HEADERS})

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    target_sources(kernel PRIVATE
        src/x64/__stack_chk_fail.S
        src/x64/call_ext.S
        src/x64/dispatch_esr_entry.S
        src/x64/dispatch_syscall_entry.S
        src/x64/fast_fail_entry.S
        src/x64/get_current_tls.S
        src/x64/mk_main_entry.S
        src/x64/return_to_current_fast_fail.S
        src/x64/return_to_mk.S
        src/x64/return_to_vmexit_loop.S
        src/x64/serial_write.S
        src/x64/set_esr.S
        src/x64/smap_guard_t.S
        src/x64/vmexit_loop_entry.S
    )
endif()

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
    target_sources(kernel PRIVATE
        src/x64/amd/intrinsic_t.S
        src/x64/amd/promote.S
    )
elseif(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    target_sources(kernel PRIVATE
        src/x64/intel/intrinsic_t.S
        src/x64/intel/promote.S
    )
else()
    message(FATAL_ERROR "Unsupported HYPERVISOR_TARGET_ARCH: ${HYPERVISOR_TARGET_ARCH}")
endif()

target_link_libraries(kernel PRIVATE
    bsl
    loader
    syscall
    hypervisor
)

install(TARGETS kernel DESTINATION bin)
