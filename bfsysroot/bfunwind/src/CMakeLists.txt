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

list(APPEND SOURCES
    dwarf4.cpp
    eh_frame.cpp
    ia64_cxx_abi.cpp
    registers_intel_x64.asm
)

if(BUILD_VMM_SHARED)
    add_library(bfunwind_shared SHARED ${SOURCES})
    set_target_properties(bfunwind_shared PROPERTIES OUTPUT_NAME "bfunwind")
    target_compile_definitions(bfunwind_shared PRIVATE SHARED_SYSCALL)
    install(TARGETS bfunwind_shared DESTINATION ${BUILD_SYSROOT_VMM}/lib)
endif()

if(BUILD_VMM_STATIC)
    add_library(bfunwind_static STATIC ${SOURCES})
    set_target_properties(bfunwind_static PROPERTIES OUTPUT_NAME "bfunwind")
    target_compile_definitions(bfunwind_static PUBLIC STATIC_SYSCALL)
    install(TARGETS bfunwind_static DESTINATION ${BUILD_SYSROOT_VMM}/lib)
endif()
