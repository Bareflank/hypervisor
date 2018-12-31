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
project(bfm C CXX)

set(C_CXX $<OR:$<COMPILE_LANGUAGE:C>,$<COMPILE_LANGUAGE:CXX>>)
set(LIN $<STREQUAL:${BUILD_TARGET_OS},Linux>)
set(WIN $<STREQUAL:${BUILD_TARGET_OS},Windows>)

init_project(bfm BINARY)

target_compile_definitions(bfm PUBLIC
    $<${C_CXX}:BFM_VMM_BIN_PATH=${BFM_VMM_BIN_PATH}>
    $<${C_CXX}:BFM_VMM_LIB_PATH=${BFM_VMM_LIB_PATH}>
    $<${C_CXX}:MAIN=main>
    $<${C_CXX}:ABORT=abort>
)

target_include_directories(bfm PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/../include>
    $<${LIN}:$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/platform/linux>>
    $<${WIN}:$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/platform/windows>>

)

target_sources(bfm PRIVATE
    $<${LIN}:platform/linux/ioctl.cpp>
    $<${LIN}:platform/linux/ioctl_private.cpp>
    $<${WIN}:platform/windows/ioctl.cpp>
    $<${WIN}:platform/windows/ioctl_private.cpp>
    command_line_parser.cpp
    ioctl_driver.cpp
    main.cpp
)

target_link_libraries(bfm PRIVATE
    ${PREFIX}::bfutil
    $<$<OR:$<BOOL:${CYGWIN}>,$<BOOL:${WIN32}>>:setupapi>
)

fini_project()
