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

add_library(bfvmm_memory_manager)
target_link_libraries(bfvmm_memory_manager PUBLIC bfvmm)

set(X64 $<STREQUAL:${BUILD_TARGET_ARCH},x86_64>)
target_sources(bfvmm_memory_manager PRIVATE
    memory_manager.cpp
    $<${X64}:arch/x64/cr3/helpers.cpp>
)

install(TARGETS bfvmm_memory_manager DESTINATION lib EXPORT bfvmm)
install(DIRECTORY ../../include/memory_manager/ DESTINATION include/bfvmm/memory_manager)
