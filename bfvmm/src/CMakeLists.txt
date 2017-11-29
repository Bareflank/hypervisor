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

add_subdirectory(debug_ring/src)
add_subdirectory(intrinsics/src)
add_subdirectory(memory_manager/src)
add_subdirectory(serial/src)
add_subdirectory(vmxon/src)
add_subdirectory(vmcs/src)
add_subdirectory(exit_handler/src)
add_subdirectory(vcpu/src)
add_subdirectory(vcpu_factory/src)
add_subdirectory(vcpu_manager/src)

if(${PROJECT_NAME} STREQUAL bfvmm_test)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/debug_ring/tests ${CMAKE_CURRENT_BINARY_DIR}/debug_ring/tests)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/intrinsics/tests ${CMAKE_CURRENT_BINARY_DIR}/intrinsics/tests)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/memory_manager/tests ${CMAKE_CURRENT_BINARY_DIR}/memory_manager/tests)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/serial/tests ${CMAKE_CURRENT_BINARY_DIR}/serial/tests)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/vmxon/tests ${CMAKE_CURRENT_BINARY_DIR}/vmxon/tests)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/vmcs/tests ${CMAKE_CURRENT_BINARY_DIR}/vmcs/tests)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/exit_handler/tests ${CMAKE_CURRENT_BINARY_DIR}/exit_handler/tests)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/vcpu/tests ${CMAKE_CURRENT_BINARY_DIR}/vcpu/tests)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/vcpu_factory/tests ${CMAKE_CURRENT_BINARY_DIR}/vcpu_factory/tests)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/vcpu_manager/tests ${CMAKE_CURRENT_BINARY_DIR}/vcpu_manager/tests)
else()
    add_subdirectory(support)
    add_subdirectory(main)
endif()
