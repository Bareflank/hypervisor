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
project(bfm C CXX)

init_project(bfm)

# -----------------------------------------------------------------------------
# Common
# -----------------------------------------------------------------------------

set(USR $<STREQUAL:${PREFIX},userspace>)

target_link_libraries(bfm PUBLIC
    ${PREFIX}::bfroot
    $<$<OR:$<BOOL:${CYGWIN}>,$<BOOL:${WIN32}>>:setupapi>
)
target_sources(bfm PRIVATE
    src/command_line_parser.cpp
    src/ioctl_driver.cpp
    src/main.cpp
)
target_compile_definitions(bfm PUBLIC
    $<BUILD_INTERFACE:$<${USR}:BFM_VMM_BIN_PATH=${BFM_VMM_BIN_PATH}>>
    $<BUILD_INTERFACE:$<${USR}:BFM_VMM_LIB_PATH=${BFM_VMM_LIB_PATH}>>
    $<BUILD_INTERFACE:$<${USR}:MAIN=main>>
    $<BUILD_INTERFACE:$<${USR}:ABORT=abort>>
)
target_include_directories(bfm PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/../bfsdk/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/../bfelf_loader/include>
)

# -----------------------------------------------------------------------------
# Userspace
# -----------------------------------------------------------------------------

if(PREFIX STREQUAL userspace)
    add_executable(bfm-binary)
    string(TOLOWER ${BUILD_TARGET_OS} OS)
    target_link_libraries(bfm-binary PRIVATE bfm)
    target_include_directories(bfm-binary PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/src/platform/${OS}>
    )
    target_sources(bfm-binary PRIVATE
        src/platform/${OS}/ioctl.cpp
        src/platform/${OS}/ioctl_private.cpp
    )
    set_target_properties(bfm-binary PROPERTIES OUTPUT_NAME bfm)
    install(TARGETS bfm-binary DESTINATION bin EXPORT bfm-userspace-targets)
endif()

# -----------------------------------------------------------------------------
# Test
# -----------------------------------------------------------------------------

if(PREFIX STREQUAL test)
    target_include_directories(bfm INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/tests>
    )
    do_test(tests/test_command_line_parser.cpp)
    do_test(tests/test_ioctl_driver.cpp)
    do_test(tests/test_main.cpp)
endif()

fini_project()
