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

if(${BUILD_TARGET_ARCH} STREQUAL "x86_64")
    list(APPEND SOURCES
        arch/intel_x64/map_ptr_x64.cpp
        arch/intel_x64/memory_manager_x64.cpp
        arch/intel_x64/page_table_entry_x64.cpp
        arch/intel_x64/page_table_x64.cpp
        arch/intel_x64/root_page_table_x64.cpp
    )
elseif(${BUILD_TARGET_ARCH} STREQUAL "aarch64")
    message(WARNING "Unimplemented")
else()
    message(FATAL_ERROR "Unsupported archiecture")
endif()

add_shared_library(
    bfvmm_memory_manager
    SOURCES ${SOURCES}
    DEFINES SHARED_MEMORY_MANAGER
    DEFINES SHARED_INTRINSICS
)

add_static_library(
    bfvmm_memory_manager
    SOURCES ${SOURCES}
    DEFINES STATIC_MEMORY_MANAGER
    DEFINES STATIC_INTRINSICS
)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(DIRECTORY ${CMAKE_SOURCE_DIR}/../../include/bfvmm/memory_manager DESTINATION include/bfvmm)
