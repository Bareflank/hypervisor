#
# Bareflank Hypervisor
# Copyright (C) 2015 Assured Information Security, Inc.
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

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

if(${BUILD_TARGET_ARCH} STREQUAL x86_64)

    list(APPEND SOURCES
        arch/intel_x64/vmcs_intel_x64.cpp
        arch/intel_x64/vmcs_intel_x64_host_vm_state.cpp
        arch/intel_x64/vmcs_intel_x64_vmm_state.cpp
    )

    if(${PROJECT_NAME} STREQUAL bfvmm_test)
        list(APPEND SOURCES arch/intel_x64/vmcs_intel_x64_launch_mock.cpp)
        list(APPEND SOURCES arch/intel_x64/vmcs_intel_x64_promote_mock.cpp)
        list(APPEND SOURCES arch/intel_x64/vmcs_intel_x64_resume_mock.cpp)
    else()
        list(APPEND SOURCES arch/intel_x64/vmcs_intel_x64_launch.asm)
        list(APPEND SOURCES arch/intel_x64/vmcs_intel_x64_promote.asm)
        list(APPEND SOURCES arch/intel_x64/vmcs_intel_x64_resume.asm)
    endif()

elseif(${BUILD_TARGET_ARCH} STREQUAL aarch64)
endif()

if(BUILD_VMM_SHARED)
    add_library(bfvmm_vmcs_shared SHARED ${SOURCES})
    set_target_properties(bfvmm_vmcs_shared PROPERTIES OUTPUT_NAME "bfvmm_vmcs")
    target_compile_definitions(bfvmm_vmcs_shared PRIVATE SHARED_VMCS)
    target_link_libraries(bfvmm_vmcs_shared bfvmm_memory_manager_shared)
    target_link_libraries(bfvmm_vmcs_shared bfvmm_intrinsics_shared)
    install(TARGETS bfvmm_vmcs_shared DESTINATION ${BUILD_SYSROOT_VMM}/lib)
endif()

if(BUILD_VMM_STATIC)
    add_library(bfvmm_vmcs_static STATIC ${SOURCES})
    set_target_properties(bfvmm_vmcs_static PROPERTIES OUTPUT_NAME "bfvmm_vmcs")
    target_compile_definitions(bfvmm_vmcs_static PUBLIC STATIC_VMCS)
    target_compile_definitions(bfvmm_vmcs_static PUBLIC STATIC_MEMORY_MANAGER)
    target_compile_definitions(bfvmm_vmcs_static PUBLIC STATIC_INTRINSICS)
    install(TARGETS bfvmm_vmcs_static DESTINATION ${BUILD_SYSROOT_VMM}/lib)
endif()
