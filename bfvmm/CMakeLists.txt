#
# Bareflank Hypervisor
# Copyright (C) 2019 Assured Information Security, Inc.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

cmake_minimum_required(VERSION 3.10)
project(bfvmm C CXX)

# ------------------------------------------------------------------------------
# Generator expressions
# ------------------------------------------------------------------------------

set(CXX $<COMPILE_LANGUAGE:CXX>)
set(WIN $<BOOL:${WIN32}>)
set(X64 $<STREQUAL:${BUILD_TARGET_ARCH},x86_64>)
set(MOCK $<BOOL:${ENABLE_MOCKING}>)
set(X64_ASM $<AND:$<NOT:${WIN}>,$<NOT:${MOCK}>,${X64}>)
set(BUILD $<BOOL:$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>>)
set(BUILD_INCLUDE $<AND:${CXX},${BUILD}>)
set(PROJECT_ROOT ${CMAKE_CURRENT_SOURCE_DIR})

# ------------------------------------------------------------------------------
# common
# ------------------------------------------------------------------------------

init_project(bfvmm INTERFACE)
target_link_libraries(bfvmm INTERFACE ${PREFIX}::bfroot)

add_subdirectory(src/hve)
add_subdirectory(src/vcpu)
add_subdirectory(src/memory_manager)
add_subdirectory(src/debug)

# ------------------------------------------------------------------------------
# test
# ------------------------------------------------------------------------------

if(PREFIX STREQUAL test)
    target_link_libraries(bfvmm INTERFACE
        bfvmm_hve
        bfvmm_vcpu
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
        bfvmm_vcpu
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
    target_include_directories(bfvmm INTERFACE $<INSTALL_INTERFACE:include/bfvmm>)
    install(DIRECTORY include/ DESTINATION include/bfvmm)

    if(BUILD_TEST)
        set(IT_DIR integration/arch/intel_x64)

        add_executable(test_efi ${IT_DIR}/efi/test_efi.cpp)
        add_executable(test_efi_with_interrupts ${IT_DIR}/efi/test_efi_with_interrupts.cpp)
        add_executable(enable_ept ${IT_DIR}/ept/enable_ept.cpp)
        add_executable(remap_page ${IT_DIR}/ept/remap_page.cpp)
        add_executable(trap_cr0 ${IT_DIR}/vmexit/control_register/trap_cr0.cpp)
        add_executable(trap_cr3 ${IT_DIR}/vmexit/control_register/trap_cr3.cpp)
        add_executable(trap_cr4 ${IT_DIR}/vmexit/control_register/trap_cr4.cpp)
        add_executable(trap_cpuid ${IT_DIR}/vmexit/cpuid/trap_cpuid.cpp)
        add_executable(trap_ept_misconfiguration ${IT_DIR}/vmexit/ept_misconfiguration/trap_ept_misconfiguration.cpp)
        add_executable(trap_ept_violation ${IT_DIR}/vmexit/ept_violation/trap_ept_violation.cpp)
        add_executable(trap_all_interrupts ${IT_DIR}/vmexit/external_interrupt/trap_all_interrupts.cpp)
        add_executable(trap_in_out ${IT_DIR}/vmexit/io_instruction/trap_in_out.cpp)
        add_executable(single_step_cpuid ${IT_DIR}/vmexit/monitor_trap/single_step_cpuid.cpp)
        add_executable(trap_rdmsr ${IT_DIR}/vmexit/rdmsr/trap_rdmsr.cpp)
        add_executable(trap_wrmsr ${IT_DIR}/vmexit/wrmsr/trap_wrmsr.cpp)
        add_executable(enable_vpid ${IT_DIR}/vpid/enable_vpid.cpp)
        add_executable(test_all ${IT_DIR}/test_all.cpp)

        target_link_libraries(test_efi PRIVATE vmm::bfvmm)
        target_link_libraries(test_efi_with_interrupts PRIVATE vmm::bfvmm)
        target_link_libraries(enable_ept PRIVATE vmm::bfvmm)
        target_link_libraries(remap_page PRIVATE vmm::bfvmm)
        target_link_libraries(trap_cr0 PRIVATE vmm::bfvmm)
        target_link_libraries(trap_cr3 PRIVATE vmm::bfvmm)
        target_link_libraries(trap_cr4 PRIVATE vmm::bfvmm)
        target_link_libraries(trap_cpuid PRIVATE vmm::bfvmm)
        target_link_libraries(trap_ept_misconfiguration PRIVATE vmm::bfvmm)
        target_link_libraries(trap_ept_violation PRIVATE vmm::bfvmm)
        target_link_libraries(trap_all_interrupts PRIVATE vmm::bfvmm)
        target_link_libraries(trap_in_out PRIVATE vmm::bfvmm)
        target_link_libraries(single_step_cpuid PRIVATE vmm::bfvmm)
        target_link_libraries(trap_rdmsr PRIVATE vmm::bfvmm)
        target_link_libraries(trap_wrmsr PRIVATE vmm::bfvmm)
        target_link_libraries(enable_vpid PRIVATE vmm::bfvmm)
        target_link_libraries(test_all PRIVATE vmm::bfvmm)

    endif()
endif()

fini_project()
