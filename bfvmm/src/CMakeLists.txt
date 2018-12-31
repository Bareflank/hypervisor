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

set(C $<COMPILE_LANGUAGE:C>)
set(CXX $<COMPILE_LANGUAGE:CXX>)
set(C_CXX $<OR:${CXX},${C}>)
set(BUILD $<BOOL:$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/../include>>)
set(NEED_INCLUDE $<AND:${C_CXX},${BUILD}>)

target_link_libraries(bfvmm INTERFACE ${PREFIX}::bfutil)

target_include_directories(bfvmm SYSTEM INTERFACE
    $<${NEED_INCLUDE}:${CMAKE_CURRENT_LIST_DIR}/../include>
)

add_subdirectory(debug)
add_subdirectory(memory_manager)
add_subdirectory(hve)
add_subdirectory(vcpu)
add_subdirectory(entry)
add_subdirectory(main)

fini_project()
