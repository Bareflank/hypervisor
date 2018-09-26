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
        arch/intel_x64/check_vmcs_control_fields.cpp
        arch/intel_x64/check_vmcs_guest_fields.cpp
        arch/intel_x64/check_vmcs_host_fields.cpp
        arch/intel_x64/exception.cpp
        arch/intel_x64/nmi.cpp
        arch/intel_x64/exit_handler.cpp
        arch/intel_x64/vmcs.cpp
        arch/intel_x64/vmx.cpp
    )

    if(NOT WIN32 AND NOT ENABLE_MOCKING)
        list(APPEND SOURCES
            arch/intel_x64/exception.asm
            arch/intel_x64/nmi.asm
            arch/intel_x64/exit_handler_entry.asm
            arch/intel_x64/vmcs_launch.asm
            arch/intel_x64/vmcs_promote.asm
            arch/intel_x64/vmcs_resume.asm
        )
    endif()
elseif(${BUILD_TARGET_ARCH} STREQUAL "aarch64")
    message(WARNING "Unimplemented")
else()
    message(FATAL_ERROR "Unsupported archiecture")
endif()

add_shared_library(
    bfvmm_hve
    SOURCES ${SOURCES}
    DEFINES SHARED_HVE
    DEFINES SHARED_MEMORY_MANAGER
    DEFINES SHARED_INTRINSICS
)

add_static_library(
    bfvmm_hve
    SOURCES ${SOURCES}
    DEFINES STATIC_HVE
    DEFINES STATIC_MEMORY_MANAGER
    DEFINES STATIC_INTRINSICS
)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(DIRECTORY ../../include/hve/ DESTINATION include/bfvmm/hve)
