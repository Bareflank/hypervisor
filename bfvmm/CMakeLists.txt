#
# Bareflank Hypervisor
# Copyright (C) 2019 Assured Information Security, Inc.
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

target_link_libraries(bfvmm INTERFACE ${PREFIX}::bfintrinsics)
target_link_directories(bfvmm INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/lib>
    $<BUILD_INTERFACE:${CMAKE_INSTALL_PREFIX}/lib>
)
target_include_directories(bfvmm SYSTEM INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
    $<INSTALL_INTERFACE:include/bfvmm>
)

add_subdirectory(src/hve)
add_subdirectory(src/vcpu)
add_subdirectory(src/memory_manager)
add_subdirectory(src/debug)

target_link_libraries(bfvmm INTERFACE bfvmm_hve)
target_link_libraries(bfvmm INTERFACE bfvmm_vcpu)
target_link_libraries(bfvmm INTERFACE bfvmm_memory_manager)
target_link_libraries(bfvmm INTERFACE bfvmm_debug)

if(PREFIX STREQUAL test)
    add_subdirectory(tests/hve ${CMAKE_CURRENT_BINARY_DIR}/tests/hve)
    add_subdirectory(tests/vcpu ${CMAKE_CURRENT_BINARY_DIR}/tests/vcpu)
    add_subdirectory(tests/memory_manager ${CMAKE_CURRENT_BINARY_DIR}/tests/memory_manager)
    add_subdirectory(tests/debug ${CMAKE_CURRENT_BINARY_DIR}/tests/debug)
elseif(PREFIX STREQUAL vmm)
    add_subdirectory(src/entry)
    add_subdirectory(src/main)
endif()

install(DIRECTORY include/ DESTINATION include)

fini_project()
