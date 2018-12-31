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
project(bfcrt C CXX)

init_project(bfcrt)

set(WIN $<BOOL:${WIN32}>)
set(CXX $<COMPILE_LANGUAGE:CXX>)
set(ARM $<STREQUAL:${BUILD_TARGET_ARCH},aarch64>)
set(X64 $<STREQUAL:${BUILD_TARGET_ARCH},x86_64>)
set(X64_AND_NOT_WIN $<AND:${X64},$<NOT:${WIN}>>)

target_compile_options(bfcrt PRIVATE $<${CXX}:-Wno-main>)
target_link_libraries(bfcrt PUBLIC ${PREFIX}::bfutil)
target_sources(bfcrt PRIVATE
    crt.cpp
    $<${X64_AND_NOT_WIN}:start_x64.asm>
    $<${ARM}:start_x64.S>
)

fini_project()
