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
    vcpu.cpp
)

add_shared_library(
    bfvmm_vcpu
    SOURCES ${SOURCES}
    DEFINES SHARED_VCPU
    DEFINES SHARED_HVE
    DEFINES SHARED_MEMORY_MANAGER
    DEFINES SHARED_INTRINSICS
)

add_static_library(
    bfvmm_vcpu
    SOURCES ${SOURCES}
    DEFINES STATIC_VCPU
    DEFINES STATIC_HVE
    DEFINES STATIC_MEMORY_MANAGER
    DEFINES STATIC_INTRINSICS
)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(DIRECTORY ../../include/vcpu/ DESTINATION include/bfvmm/vcpu)
