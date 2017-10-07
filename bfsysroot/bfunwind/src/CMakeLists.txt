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
    dwarf4.cpp
    eh_frame.cpp
    ia64_cxx_abi.cpp
    registers_intel_x64.asm
)

if(BUILD_SHARED_LIBS)
    add_library(bfunwind SHARED ${SOURCES})
    target_compile_definitions(bfunwind PRIVATE SHARED_SYSCALL)
endif()

if(BUILD_STATIC_LIBS)
    add_library(bfunwind STATIC ${SOURCES})
    target_compile_definitions(bfunwind PUBLIC STATIC_SYSCALL)
endif()

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(TARGETS bfunwind DESTINATION ${INSTALL_LIB_DIR})
