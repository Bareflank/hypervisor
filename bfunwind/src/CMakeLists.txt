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
project(bfunwind C CXX)

init_project(bfunwind)

set(C $<COMPILE_LANGUAGE:C>)
set(CXX $<COMPILE_LANGUAGE:CXX>)
set(C_OR_CXX $<OR:${CXX},${C}>)
set(BUILD $<BOOL:$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/../include>>)
set(NEED_INCLUDE $<AND:${C_OR_CXX},${BUILD}>)

target_link_libraries(bfunwind PUBLIC bfpthread bfsyscall bfcrt)
target_include_directories(bfunwind PUBLIC
    $<${NEED_INCLUDE}:${CMAKE_CURRENT_LIST_DIR}/../include>
)
target_sources(bfunwind PRIVATE
    dwarf4.cpp
    eh_frame.cpp
    ia64_cxx_abi.cpp
    registers_intel_x64.asm
)
install(FILES ../include/ia64_cxx_abi.h DESTINATION include RENAME unwind.h)
fini_project()
