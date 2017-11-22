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
        arch/intel_x64/vmxon_intel_x64.cpp
    )
elseif(${BUILD_TARGET_ARCH} STREQUAL aarch64)
endif()

if(BUILD_VMM_SHARED)
    add_library(bfvmm_vmxon_shared SHARED ${SOURCES})
    set_target_properties(bfvmm_vmxon_shared PROPERTIES OUTPUT_NAME "bfvmm_vmxon")
    target_compile_definitions(bfvmm_vmxon_shared PRIVATE SHARED_VMXON)
    target_link_libraries(bfvmm_vmxon_shared bfvmm_memory_manager_shared)
    target_link_libraries(bfvmm_vmxon_shared bfvmm_intrinsics_shared)
    install(TARGETS bfvmm_vmxon_shared DESTINATION ${BUILD_SYSROOT_VMM}/lib)
endif()

if(BUILD_VMM_STATIC)
    add_library(bfvmm_vmxon_static STATIC ${SOURCES})
    set_target_properties(bfvmm_vmxon_static PROPERTIES OUTPUT_NAME "bfvmm_vmxon")
    target_compile_definitions(bfvmm_vmxon_static PUBLIC STATIC_VMXON)
    target_compile_definitions(bfvmm_vmxon_static PUBLIC STATIC_MEMORY_MANAGER)
    target_compile_definitions(bfvmm_vmxon_static PUBLIC STATIC_INTRINSICS)
    install(TARGETS bfvmm_vmxon_static DESTINATION ${BUILD_SYSROOT_VMM}/lib)
endif()
