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

cmake_minimum_required(VERSION 3.13)
project(bfunwind C CXX)

init_project(bfunwind)

set(BUILD $<BOOL:$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>>)
set(C_CXX $<OR:$<COMPILE_LANGUAGE:C>,$<COMPILE_LANGUAGE:CXX>>)
set(BUILD_INCLUDE $<AND:${C_CXX},${BUILD}>)

target_link_libraries(bfunwind PUBLIC ${PREFIX}::bfroot)
target_include_directories(bfunwind PUBLIC
    $<${BUILD_INCLUDE}:${CMAKE_CURRENT_LIST_DIR}/include>
    $<${BUILD_INCLUDE}:${CMAKE_CURRENT_LIST_DIR}/../bfsdk/include>
)
target_sources(bfunwind PRIVATE
    src/dwarf4.cpp
    src/eh_frame.cpp
    src/ia64_cxx_abi.cpp
    src/registers_intel_x64.asm
)

# -----------------------------------------------------------------------------
# Install
# -----------------------------------------------------------------------------

install(
    FILES ${CMAKE_CURRENT_LIST_DIR}/include/ia64_cxx_abi.h
    DESTINATION include
    RENAME unwind.h
)

fini_project()
