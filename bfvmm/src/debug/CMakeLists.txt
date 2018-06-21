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
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    debug_ring/debug_ring.cpp
    serial/serial_ns16550a.cpp
    # serial/serial_pl011.cpp
)

if(${BUILD_TARGET_ARCH} STREQUAL "x86_64")
    list(APPEND SOURCES
        arch/x64/serial_ns16550a.cpp
    )
endif()

if(${BUILD_TARGET_ARCH} STREQUAL "aarch64")
    list(APPEND SOURCES
        arch/aarch64/serial_ns16550a.cpp
    )
endif()

if(NOT ENABLE_MOCKING)
    list(APPEND SOURCES
        unistd.cpp
    )
endif()

add_shared_library(
    bfvmm_debug
    SOURCES ${SOURCES}
    DEFINES SHARED_DEBUG
    DEFINES SHARED_INTRINSICS
)

add_static_library(
    bfvmm_debug
    SOURCES ${SOURCES}
    DEFINES STATIC_DEBUG
    DEFINES STATIC_INTRINSICS
)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(DIRECTORY ../../include/debug/ DESTINATION include/bfvmm/debug)
