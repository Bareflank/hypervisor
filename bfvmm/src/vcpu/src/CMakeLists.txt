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

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    vcpu.cpp
    vcpu_intel_x64.cpp
)

if(BUILD_SHARED_LIBS)
    add_library(bfvmm_vcpu SHARED ${SOURCES})
    target_compile_definitions(bfvmm_vcpu PRIVATE SHARED_VCPU)
    target_link_libraries(bfvmm_vcpu bfvmm_vmxon)
    target_link_libraries(bfvmm_vcpu bfvmm_exit_handler)
    target_link_libraries(bfvmm_vcpu bfvmm_vmcs)
    target_link_libraries(bfvmm_vcpu bfvmm_memory_manager)
    target_link_libraries(bfvmm_vcpu bfvmm_intrinsics)
endif()

if(BUILD_STATIC_LIBS)
    add_library(bfvmm_vcpu STATIC ${SOURCES})
    target_compile_definitions(bfvmm_vcpu PUBLIC STATIC_VCPU)
    target_compile_definitions(bfvmm_vcpu PUBLIC STATIC_VMXON)
    target_compile_definitions(bfvmm_vcpu PUBLIC STATIC_EXIT_HANDLER)
    target_compile_definitions(bfvmm_vcpu PUBLIC STATIC_VMCS)
    target_compile_definitions(bfvmm_vcpu PUBLIC STATIC_MEMORY_MANAGER)
    target_compile_definitions(bfvmm_vcpu PUBLIC STATIC_INTRINSICS)
endif()

install(TARGETS bfvmm_vcpu DESTINATION ${INSTALL_LIB_DIR})
