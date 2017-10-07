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
    debug_ring.cpp
)

if(BUILD_SHARED_LIBS)
    add_library(bfvmm_debug_ring SHARED ${SOURCES})
    target_compile_definitions(bfvmm_debug_ring PRIVATE SHARED_DEBUG_RING)
endif()

if(BUILD_STATIC_LIBS)
    add_library(bfvmm_debug_ring STATIC ${SOURCES})
    target_compile_definitions(bfvmm_debug_ring PUBLIC STATIC_DEBUG_RING)
endif()

install(TARGETS bfvmm_debug_ring DESTINATION ${INSTALL_LIB_DIR})
