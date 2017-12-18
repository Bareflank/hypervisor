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
# README
# ------------------------------------------------------------------------------

# This file gets included by all Bareflank extensions to provide convinience
# macros for intercting with the base Bareflank build system. These macros
# are for use by Bareflank extensions only (not the base build system).

# Link the given target with all bfvmm and support libraries
# @arg target: The target to be linked with bfvmm libraries
macro(link_vmm_libs target)
    if(VMM_EX_IS_UNITTEST_BUILD)
        target_link_libraries(${target} bfcrt_userspace)
        target_link_libraries(${target} test_catch)
    else()
        target_link_libraries(${target} -Wl,--whole-archive bfvmm_main -Wl,--no-whole-archive)
        target_link_libraries(${target} --whole-archive -lbfcrt --no-whole-archive)
        target_link_libraries(${target} c++)
        target_link_libraries(${target} c++abi)
        target_link_libraries(${target} pthread)
        target_link_libraries(${target} bfunwind)
        target_link_libraries(${target} bfsyscall)
        target_link_libraries(${target} c)
    endif()

    target_link_libraries(${target} bfvmm_support)
    target_link_libraries(${target} bfvmm_vcpu_factory)
    target_link_libraries(${target} bfvmm_vcpu)
    target_link_libraries(${target} bfvmm_vcpu_manager)
    target_link_libraries(${target} bfvmm_exit_handler)
    target_link_libraries(${target} bfvmm_vmcs)
    target_link_libraries(${target} bfvmm_vmxon)
    target_link_libraries(${target} bfvmm_memory_manager)
    target_link_libraries(${target} bfvmm_serial)
    target_link_libraries(${target} bfvmm_debug_ring)
    target_link_libraries(${target} bfvmm_intrinsics)
endmacro(link_vmm_libs)

# Create a VMM executable to be linked with all bfvmm and support libraries
# Usage: call add_vmm_executable() with any arguments supported by cmake's
# built-in add_excecutable() function
macro(add_vmm_executable)
    add_executable(${ARGN})
    set(ARGS ${ARGN})
    list(GET ARGS 0 EXE_NAME)
    link_vmm_libs(${EXE_NAME})
endmacro(add_vmm_executable)

# Create a VMM library to be linked with all bfvmm and support libraries
# Usage: call add_vmm_library() with any arguments supported by cmake's
# built-in add_library() function
macro(add_vmm_library)
    add_library(${ARGN})
    set(ARGS ${ARGN})
    list(GET ARGS 0 LIB_NAME)
    link_vmm_libs(${LIB_NAME})
endmacro(add_vmm_library)

# Install executables to the base build system's vmm sysroot binary directory
# @arg target: The name of the target to be installed
macro(install_vmm_executable target)
    install(TARGETS ${target} DESTINATION ${VMM_EX_SYSROOT}/bin)
endmacro(install_vmm_executable)

# Install libraries to the base build system's vmm sysroot library directory
# @arg target: The name of the target to be installed
macro(install_vmm_library target)
    install(TARGETS ${target} DESTINATION ${VMM_EX_SYSROOT}/lib)
endmacro(install_vmm_library)
