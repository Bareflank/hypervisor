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
    vmcs_intel_x64.cpp
    vmcs_intel_x64_host_vm_state.cpp
    vmcs_intel_x64_vmm_state.cpp
)

if(CMAKE_TOOLCHAIN_FILE)
    list(APPEND SOURCES vmcs_intel_x64_launch.asm)
    list(APPEND SOURCES vmcs_intel_x64_promote.asm)
    list(APPEND SOURCES vmcs_intel_x64_resume.asm)
else()
    list(APPEND SOURCES vmcs_intel_x64_launch_mock.cpp)
    list(APPEND SOURCES vmcs_intel_x64_promote_mock.cpp)
    list(APPEND SOURCES vmcs_intel_x64_resume_mock.cpp)
endif()

if(BUILD_SHARED_LIBS)
    add_library(bfvmm_vmcs SHARED ${SOURCES})
    target_compile_definitions(bfvmm_vmcs PRIVATE SHARED_VMCS)
    target_link_libraries(bfvmm_vmcs bfvmm_memory_manager)
    target_link_libraries(bfvmm_vmcs bfvmm_intrinsics)
endif()

if(BUILD_STATIC_LIBS)
    add_library(bfvmm_vmcs STATIC ${SOURCES})
    target_compile_definitions(bfvmm_vmcs PUBLIC STATIC_VMCS)
    target_compile_definitions(bfvmm_vmcs PUBLIC STATIC_MEMORY_MANAGER)
    target_compile_definitions(bfvmm_vmcs PUBLIC STATIC_INTRINSICS)
endif()

install(TARGETS bfvmm_vmcs DESTINATION ${INSTALL_LIB_DIR})
