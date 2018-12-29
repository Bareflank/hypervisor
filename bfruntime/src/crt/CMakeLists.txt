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
set(ARCH ${BUILD_TARGET_ARCH})
set(NOT_WIN32 $<NOT:$<BOOL:${WIN32}>>)
target_link_libraries(bfcrt PUBLIC bfutil)
target_compile_options(bfcrt PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-Wno-main>)
target_sources(bfcrt PRIVATE
    crt.cpp
    $<$<AND:$<STREQUAL:${ARCH},x86_64>,${NOT_WIN32}>:start_x64.asm>
    $<$<STREQUAL:${BUILD_TARGET_ARCH},aarch64>:start_x64.S>
)
fini_project()
