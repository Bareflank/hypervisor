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

add_executable(kernel)

# ------------------------------------------------------------------------------
# Includes
# ------------------------------------------------------------------------------

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
        target_include_directories(kernel PRIVATE
            include/x64/amd
            src/x64/amd
        )
    endif()

    if(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
        target_include_directories(kernel PRIVATE
            include/x64/intel
            src/x64/intel
        )
    endif()

    target_include_directories(kernel PRIVATE
        include/x64
        src/x64
    )
endif()

if(HYPERVISOR_TARGET_ARCH STREQUAL "aarch64")
    target_include_directories(kernel PRIVATE
        include/arm/aarch64
        src/arm/aarch64
    )
endif()

target_include_directories(kernel PRIVATE
    include
    src
)

# ------------------------------------------------------------------------------
# Headers
# ------------------------------------------------------------------------------

list(APPEND HEADERS
    ${CMAKE_CURRENT_LIST_DIR}/include/call_ext.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/get_current_tls.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/promote.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/return_to_mk.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/return_to_vmexit_loop.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/serial_write_c.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/serial_write_hex.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/vmexit_loop_entry.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/bfelf/elf64_ehdr_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/bfelf/elf64_phdr_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/bfelf/elf64_shdr_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/debug_ring_write.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_esr_page_fault.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_syscall.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_syscall_callback_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_syscall_control_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_syscall_debug_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_syscall_handle_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_syscall_mem_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_syscall_vm_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_syscall_vp_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_syscall_vs_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/ext_pool_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/ext_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/fast_fail.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/huge_pool_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/mk_main_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/root_page_table_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/serial_write.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/vm_pool_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/vm_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/vmexit_loop.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/vp_pool_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/vp_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/vs_pool_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/bsl/cstdio.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/bsl/details/print_thread_id.hpp
)

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    list(APPEND HEADERS
        ${CMAKE_CURRENT_LIST_DIR}/include/x64/general_purpose_regs_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/include/x64/tls_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/include/x64/vmexit_log_pp_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/include/x64/vmexit_log_record_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/dispatch_esr.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/dispatch_syscall_intrinsic_op.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/vmexit_log_t.hpp
    )

    if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
        list(APPEND HEADERS
            ${CMAKE_CURRENT_LIST_DIR}/include/x64/amd/vmcb_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/amd/dispatch_esr_nmi.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/amd/intrinsic_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/amd/vs_t.hpp
        )
    endif()

    if(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
        list(APPEND HEADERS
            ${CMAKE_CURRENT_LIST_DIR}/include/x64/intel/invept_descriptor_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/include/x64/intel/invvpid_descriptor_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/include/x64/intel/vmcs_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/dispatch_esr_nmi.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/intrinsic_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/vs_t.hpp
        )
    endif()
endif()

if(HYPERVISOR_TARGET_ARCH STREQUAL "aarch64")
    list(APPEND HEADERS
        ${CMAKE_CURRENT_LIST_DIR}/include/arm/aarch64/general_purpose_regs_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/include/arm/aarch64/l0t_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/include/arm/aarch64/l0te_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/include/arm/aarch64/l1t_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/include/arm/aarch64/l1te_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/include/arm/aarch64/l2t_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/include/arm/aarch64/l2te_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/include/arm/aarch64/l3t_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/include/arm/aarch64/l3te_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/include/arm/aarch64/tls_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/include/arm/aarch64/vmcb_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/include/arm/aarch64/vmexit_log_pp_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/include/arm/aarch64/vmexit_log_record_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/arm/aarch64/dispatch_esr.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/arm/aarch64/dispatch_syscall_intrinsic_op.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/arm/aarch64/intrinsic_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/arm/aarch64/root_page_table_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/arm/aarch64/vmexit_log_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/arm/aarch64/vs_t.hpp
    )
endif()

# ------------------------------------------------------------------------------
# Sources
# ------------------------------------------------------------------------------

hypervisor_target_source(kernel src/main.cpp ${HEADERS})
hypervisor_target_source(kernel src/msg_halt.cpp ${HEADERS})
hypervisor_target_source(kernel src/msg_stack_chk_fail.cpp ${HEADERS})

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    hypervisor_target_source(kernel src/x64/__stack_chk_fail.S ${HEADERS})
    hypervisor_target_source(kernel src/x64/call_ext.S ${HEADERS})
    hypervisor_target_source(kernel src/x64/dispatch_esr_entry.S ${HEADERS})
    hypervisor_target_source(kernel src/x64/dispatch_syscall_entry.S ${HEADERS})
    hypervisor_target_source(kernel src/x64/fast_fail_entry.S ${HEADERS})
    hypervisor_target_source(kernel src/x64/get_current_tls.S ${HEADERS})
    hypervisor_target_source(kernel src/x64/mk_main_entry.S ${HEADERS})
    hypervisor_target_source(kernel src/x64/pause.S ${HEADERS})
    hypervisor_target_source(kernel src/x64/return_to_current_fast_fail.S ${HEADERS})
    hypervisor_target_source(kernel src/x64/return_to_mk.S ${HEADERS})
    hypervisor_target_source(kernel src/x64/return_to_vmexit_loop.S ${HEADERS})
    hypervisor_target_source(kernel src/x64/serial_write_c.S ${HEADERS})
    hypervisor_target_source(kernel src/x64/serial_write_hex.S ${HEADERS})
    hypervisor_target_source(kernel src/x64/set_esr.S ${HEADERS})
    hypervisor_target_source(kernel src/x64/vmexit_loop_entry.S ${HEADERS})

    if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
        hypervisor_target_source(kernel src/x64/amd/intrinsic_t.S ${HEADERS})
        hypervisor_target_source(kernel src/x64/amd/promote.S ${HEADERS})
    endif()

    if(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
        hypervisor_target_source(kernel src/x64/intel/intrinsic_t.S ${HEADERS})
        hypervisor_target_source(kernel src/x64/intel/promote.S ${HEADERS})
    endif()
endif()

# if(HYPERVISOR_TARGET_ARCH STREQUAL "aarch64")
#     hypervisor_target_source(kernel src/arm/aarch64/__stack_chk_fail.S ${HEADERS})
#     hypervisor_target_source(kernel src/arm/aarch64/call_ext.S ${HEADERS})
#     hypervisor_target_source(kernel src/arm/aarch64/dispatch_esr_entry.S ${HEADERS})
#     hypervisor_target_source(kernel src/arm/aarch64/dispatch_syscall_entry.S ${HEADERS})
#     hypervisor_target_source(kernel src/arm/aarch64/fast_fail_entry.S ${HEADERS})
#     hypervisor_target_source(kernel src/arm/aarch64/get_current_tls.S ${HEADERS})
#     hypervisor_target_source(kernel src/arm/aarch64/intrinsic_t.S ${HEADERS})
#     hypervisor_target_source(kernel src/arm/aarch64/mk_main_entry.S ${HEADERS})
#     hypervisor_target_source(kernel src/arm/aarch64/pause.S ${HEADERS})
#     hypervisor_target_source(kernel src/arm/aarch64/promote.S ${HEADERS})
#     hypervisor_target_source(kernel src/arm/aarch64/return_to_current_fast_fail.S ${HEADERS})
#     hypervisor_target_source(kernel src/arm/aarch64/return_to_mk.S ${HEADERS})
#     hypervisor_target_source(kernel src/arm/aarch64/return_to_vmexit_loop.S ${HEADERS})
#     hypervisor_target_source(kernel src/arm/aarch64/serial_write_c.S ${HEADERS})
#     hypervisor_target_source(kernel src/arm/aarch64/serial_write_hex.S ${HEADERS})
#     hypervisor_target_source(kernel src/arm/aarch64/vmexit_loop_entry.S ${HEADERS})
# endif()

# ------------------------------------------------------------------------------
# Libraries
# ------------------------------------------------------------------------------

target_link_libraries(kernel PRIVATE
    bsl
    loader
    syscall
    hypervisor
    lib
)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

# if(CMAKE_BUILD_TYPE STREQUAL RELEASE OR CMAKE_BUILD_TYPE STREQUAL MINSIZEREL)
#     add_custom_command(TARGET kernel POST_BUILD COMMAND ${CMAKE_STRIP} kernel)
# endif()

install(TARGETS kernel DESTINATION bin)
