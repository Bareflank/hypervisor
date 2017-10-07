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
    exit_handler_intel_x64.cpp
    exit_handler_intel_x64_entry.cpp
)

if(CMAKE_TOOLCHAIN_FILE)
    list(APPEND SOURCES exit_handler_intel_x64_support.asm)
else()
    list(APPEND SOURCES exit_handler_intel_x64_support_mock.cpp)
endif()

if(BUILD_SHARED_LIBS)
    add_library(bfvmm_exit_handler SHARED ${SOURCES})
    target_compile_definitions(bfvmm_exit_handler PRIVATE SHARED_EXIT_HANDLER)
endif()

if(BUILD_STATIC_LIBS)
    add_library(bfvmm_exit_handler STATIC ${SOURCES})
    target_compile_definitions(bfvmm_exit_handler PUBLIC STATIC_EXIT_HANDLER)
    target_compile_definitions(bfvmm_exit_handler PUBLIC STATIC_VMCS)
    target_compile_definitions(bfvmm_exit_handler PUBLIC STATIC_MEMORY_MANAGER)
    target_compile_definitions(bfvmm_exit_handler PUBLIC STATIC_INTRINSICS)
endif()

install(TARGETS bfvmm_exit_handler DESTINATION ${INSTALL_LIB_DIR})
