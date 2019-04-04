#
# Copyright (C) 2019 Assured Information Security, Inc.
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

cmake_minimum_required(VERSION 3.13)
project(bfvmm C CXX)

init_project(bfvmm INTERFACE)

# ------------------------------------------------------------------------------
# Generator expressions
# ------------------------------------------------------------------------------

set(WIN $<BOOL:${WIN32}>)
set(CXX $<COMPILE_LANGUAGE:CXX>)
set(X64 $<STREQUAL:${BUILD_TARGET_ARCH},x86_64>)
set(MOCK $<BOOL:${ENABLE_MOCKING}>)
set(X64_ASM $<AND:$<NOT:${WIN}>,$<NOT:${MOCK}>,${X64}>)
set(BUILD $<BOOL:$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>>)
set(BUILD_INCLUDE $<AND:${CXX},${BUILD}>)
set(PROJECT_ROOT ${CMAKE_CURRENT_SOURCE_DIR})

# ------------------------------------------------------------------------------
# common
# ------------------------------------------------------------------------------

target_link_libraries(bfvmm INTERFACE ${PREFIX}::bfroot)

add_subdirectory(src/hve)
add_subdirectory(src/memory_manager)
add_subdirectory(src/debug)

install(FILES include/vmm.h DESTINATION include/bfvmm)
install(DIRECTORY include/debug/ DESTINATION include/bfvmm/debug)
install(DIRECTORY include/hve/ DESTINATION include/bfvmm/hve)
install(DIRECTORY include/memory_manager/ DESTINATION include/bfvmm/memory_manager)
install(DIRECTORY include/vcpu/ DESTINATION include/bfvmm/vcpu)

# ------------------------------------------------------------------------------
# test
# ------------------------------------------------------------------------------

if(PREFIX STREQUAL test)
    target_link_libraries(bfvmm INTERFACE
        bfvmm_hve
        bfvmm_memory_manager
        bfvmm_debug
    )
    add_subdirectory(tests/hve ${CMAKE_CURRENT_BINARY_DIR}/tests/hve)
    add_subdirectory(tests/vcpu ${CMAKE_CURRENT_BINARY_DIR}/tests/vcpu)
    add_subdirectory(tests/memory_manager ${CMAKE_CURRENT_BINARY_DIR}/tests/memory_manager)
    add_subdirectory(tests/debug ${CMAKE_CURRENT_BINARY_DIR}/tests/debug)
endif()

# ------------------------------------------------------------------------------
# vmm
# ------------------------------------------------------------------------------

if(PREFIX STREQUAL vmm)
    add_subdirectory(src/entry)
    add_dependencies(bfvmm bfvmm_entry)
    target_link_libraries(bfvmm INTERFACE
        --whole-archive
        -lbfcrt
        -lbfdso
        $<BUILD_INTERFACE:bfvmm_entry>
        $<INSTALL_INTERFACE:-lbfvmm_entry>
        --no-whole-archive
        bfvmm_hve
        bfvmm_memory_manager
        bfvmm_debug
        vmm::bfintrinsics
        ${CMAKE_INSTALL_PREFIX}/lib/libc++.a
        ${CMAKE_INSTALL_PREFIX}/lib/libc++abi.a
        vmm::bfpthread
        vmm::bfunwind
        ${CMAKE_INSTALL_PREFIX}/lib/libm.a
        ${CMAKE_INSTALL_PREFIX}/lib/libc.a
        vmm::bfsyscall
    )

    add_subdirectory(src/main)
    target_include_directories(bfvmm INTERFACE
        $<INSTALL_INTERFACE:include/bfvmm>
    )

    set(INT integration/arch/intel_x64)

    if(ENABLE_BUILD_EFI)
        add_executable(test_efi ${INT}/efi/test_efi.cpp)
        add_executable(test_efi_with_interrupts ${INT}/efi/test_efi_with_interrupts.cpp)
        target_link_libraries(test_efi PRIVATE vmm::bfvmm)
        target_link_libraries(test_efi_with_interrupts PRIVATE vmm::bfvmm)
        target_include_directories(test_efi PRIVATE include)
        target_include_directories(test_efi_with_interrupts PRIVATE include)
        install(TARGETS test_efi DESTINATION bin EXPORT bfvmm-vmm-targets)
        install(TARGETS test_efi_with_interrupts DESTINATION bin EXPORT bfvmm-vmm-targets)
    endif()

    if(ENABLE_BUILD_TEST)
        add_executable(enable_ept ${INT}/ept/enable_ept.cpp)
        add_executable(remap_page ${INT}/ept/remap_page.cpp)
        add_executable(trap_cr0 ${INT}/vmexit/control_register/trap_cr0.cpp)
        add_executable(trap_cr3 ${INT}/vmexit/control_register/trap_cr3.cpp)
        add_executable(trap_cr4 ${INT}/vmexit/control_register/trap_cr4.cpp)
        add_executable(trap_cpuid ${INT}/vmexit/cpuid/trap_cpuid.cpp)
        # add_executable(trap_ept_execute_violation ${INT}/vmexit/ept_violation/trap_ept_execute_violation.cpp)
        # add_executable(trap_ept_read_violation ${INT}/vmexit/ept_violation/trap_ept_read_violation.cpp)
        # add_executable(trap_ept_write_violation ${INT}/vmexit/ept_violation/trap_ept_write_violation.cpp)
        add_executable(trap_all_interrupts ${INT}/vmexit/external_interrupt/trap_all_interrupts.cpp)
        add_executable(trap_in_out ${INT}/vmexit/io_instruction/trap_in_out.cpp)
        add_executable(single_step_cpuid ${INT}/vmexit/monitor_trap/single_step_cpuid.cpp)
        add_executable(trap_rdmsr ${INT}/vmexit/rdmsr/trap_rdmsr.cpp)
        add_executable(trap_wrmsr ${INT}/vmexit/wrmsr/trap_wrmsr.cpp)
        add_executable(enable_vpid ${INT}/vpid/enable_vpid.cpp)
        add_executable(test_all ${INT}/test_all.cpp)

        target_link_libraries(enable_ept PRIVATE vmm::bfvmm)
        target_link_libraries(remap_page PRIVATE vmm::bfvmm)
        target_link_libraries(trap_cr0 PRIVATE vmm::bfvmm)
        target_link_libraries(trap_cr3 PRIVATE vmm::bfvmm)
        target_link_libraries(trap_cr4 PRIVATE vmm::bfvmm)
        target_link_libraries(trap_cpuid PRIVATE vmm::bfvmm)
        # target_link_libraries(trap_ept_execute_violation PRIVATE vmm::bfvmm)
        # target_link_libraries(trap_ept_read_violation PRIVATE vmm::bfvmm)
        # target_link_libraries(trap_ept_write_violation PRIVATE vmm::bfvmm)
        target_link_libraries(trap_all_interrupts PRIVATE vmm::bfvmm)
        target_link_libraries(trap_in_out PRIVATE vmm::bfvmm)
        target_link_libraries(single_step_cpuid PRIVATE vmm::bfvmm)
        target_link_libraries(trap_rdmsr PRIVATE vmm::bfvmm)
        target_link_libraries(trap_wrmsr PRIVATE vmm::bfvmm)
        target_link_libraries(enable_vpid PRIVATE vmm::bfvmm)
        target_link_libraries(test_all PRIVATE vmm::bfvmm)

        target_include_directories(enable_ept PRIVATE include)
        target_include_directories(remap_page PRIVATE include)
        target_include_directories(trap_cr0 PRIVATE include)
        target_include_directories(trap_cr3 PRIVATE include)
        target_include_directories(trap_cr4 PRIVATE include)
        target_include_directories(trap_cpuid PRIVATE include)
        # target_include_directories(trap_ept_execute_violation PRIVATE include)
        # target_include_directories(trap_ept_read_violation PRIVATE include)
        # target_include_directories(trap_ept_write_violation PRIVATE include)
        target_include_directories(trap_all_interrupts PRIVATE include)
        target_include_directories(trap_in_out PRIVATE include)
        target_include_directories(single_step_cpuid PRIVATE include)
        target_include_directories(trap_rdmsr PRIVATE include)
        target_include_directories(trap_wrmsr PRIVATE include)
        target_include_directories(enable_vpid PRIVATE include)
        target_include_directories(test_all PRIVATE include)

        install(TARGETS enable_ept DESTINATION bin EXPORT bfvmm-vmm-targets)
        install(TARGETS remap_page DESTINATION bin EXPORT bfvmm-vmm-targets)
        install(TARGETS trap_cr0 DESTINATION bin EXPORT bfvmm-vmm-targets)
        install(TARGETS trap_cr3 DESTINATION bin EXPORT bfvmm-vmm-targets)
        install(TARGETS trap_cr4 DESTINATION bin EXPORT bfvmm-vmm-targets)
        install(TARGETS trap_cpuid DESTINATION bin EXPORT bfvmm-vmm-targets)
        # install(TARGETS trap_ept_execute_violation DESTINATION bin EXPORT bfvmm-vmm-targets)
        # install(TARGETS trap_ept_read_violation DESTINATION bin EXPORT bfvmm-vmm-targets)
        # install(TARGETS trap_ept_write_violation DESTINATION bin EXPORT bfvmm-vmm-targets)
        install(TARGETS trap_all_interrupts DESTINATION bin EXPORT bfvmm-vmm-targets)
        install(TARGETS trap_in_out DESTINATION bin EXPORT bfvmm-vmm-targets)
        install(TARGETS single_step_cpuid DESTINATION bin EXPORT bfvmm-vmm-targets)
        install(TARGETS trap_rdmsr DESTINATION bin EXPORT bfvmm-vmm-targets)
        install(TARGETS trap_wrmsr DESTINATION bin EXPORT bfvmm-vmm-targets)
        install(TARGETS enable_vpid DESTINATION bin EXPORT bfvmm-vmm-targets)
        install(TARGETS test_all DESTINATION bin EXPORT bfvmm-vmm-targets)

    endif()
endif()

fini_project()
