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

cmake_minimum_required(VERSION 3.10)
project(bfvmm C CXX)

init_project(bfvmm INTERFACE)

target_link_libraries(bfvmm INTERFACE vmm::bfutil)
target_link_directories(bfvmm INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/lib>
    $<BUILD_INTERFACE:${CMAKE_INSTALL_PREFIX}/lib>
)
target_include_directories(bfvmm SYSTEM INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/../include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/../../bfintrinsics/include>
    $<INSTALL_INTERFACE:include/bfvmm>
)

add_subdirectory(debug)
add_subdirectory(memory_manager)
add_subdirectory(hve)
add_subdirectory(vcpu)
add_subdirectory(entry)
add_subdirectory(main)

fini_project()
