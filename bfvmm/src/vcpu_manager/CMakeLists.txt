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

if(${BUILD_TARGET_ARCH} STREQUAL x86_64)
    list(APPEND SOURCES
        vcpu_manager.cpp
    )
elseif(${BUILD_TARGET_ARCH} STREQUAL aarch64)
    list(APPEND SOURCES
        vcpu_manager.cpp
    )
endif()

if(BUILD_VMM_SHARED)
    add_library(bfvmm_vcpu_manager_shared SHARED ${SOURCES})
    set_target_properties(bfvmm_vcpu_manager_shared PROPERTIES OUTPUT_NAME "bfvmm_vcpu_manager")
    target_compile_definitions(bfvmm_vcpu_manager_shared PRIVATE SHARED_VCPU)
    target_link_libraries(bfvmm_vcpu_manager_shared bfvmm_vcpu_shared)
    target_link_libraries(bfvmm_vcpu_manager_shared bfvmm_vcpu_factory_shared)
    target_link_libraries(bfvmm_vcpu_manager_shared bfvmm_vmxon_shared)
    target_link_libraries(bfvmm_vcpu_manager_shared bfvmm_exit_handler_shared)
    target_link_libraries(bfvmm_vcpu_manager_shared bfvmm_vmcs_shared)
    target_link_libraries(bfvmm_vcpu_manager_shared bfvmm_memory_manager_shared)
    target_link_libraries(bfvmm_vcpu_manager_shared bfvmm_intrinsics_shared)
    install(TARGETS bfvmm_vcpu_manager_shared DESTINATION ${BUILD_SYSROOT_VMM}/lib)
endif()

if(BUILD_VMM_STATIC)
    add_library(bfvmm_vcpu_manager_static STATIC ${SOURCES})
    set_target_properties(bfvmm_vcpu_manager_static PROPERTIES OUTPUT_NAME "bfvmm_vcpu_manager")
    target_compile_definitions(bfvmm_vcpu_manager_static PUBLIC STATIC_VCPU)
    target_compile_definitions(bfvmm_vcpu_manager_static PUBLIC STATIC_VMXON)
    target_compile_definitions(bfvmm_vcpu_manager_static PUBLIC STATIC_EXIT_HANDLER)
    target_compile_definitions(bfvmm_vcpu_manager_static PUBLIC STATIC_VMCS)
    target_compile_definitions(bfvmm_vcpu_manager_static PUBLIC STATIC_MEMORY_MANAGER)
    target_compile_definitions(bfvmm_vcpu_manager_static PUBLIC STATIC_INTRINSICS)
    install(TARGETS bfvmm_vcpu_manager_static DESTINATION ${BUILD_SYSROOT_VMM}/lib)
endif()
