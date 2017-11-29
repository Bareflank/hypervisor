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
    unistd.cpp
)

if(BUILD_VMM_SHARED)
    add_library(bfvmm_support_shared SHARED ${SOURCES})
    set_target_properties(bfvmm_support_shared PROPERTIES OUTPUT_NAME "bfvmm_support")
    install(TARGETS bfvmm_support_shared DESTINATION ${BUILD_SYSROOT_VMM}/lib)
endif()

if(BUILD_VMM_STATIC)
    add_library(bfvmm_support_static STATIC ${SOURCES})
    set_target_properties(bfvmm_support_static PROPERTIES OUTPUT_NAME "bfvmm_support")
    install(TARGETS bfvmm_support_static DESTINATION ${BUILD_SYSROOT_VMM}/lib)
endif()
