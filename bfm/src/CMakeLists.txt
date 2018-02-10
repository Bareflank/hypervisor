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

cmake_minimum_required(VERSION 3.6)
project(bfruntime C CXX)

list(APPEND BFM_CXX_FLAGS
    -DBFM_VMM_BIN_PATH=${BFM_VMM_BIN_PATH}
    -DBFM_VMM_LIB_PATH=${BFM_VMM_LIB_PATH}
)

include(${SOURCE_CMAKE_DIR}/project.cmake)
init_project(
    INCLUDES ${CMAKE_CURRENT_LIST_DIR}/../include
    CXX_FLAGS ${BFM_CXX_FLAGS}
)

if(BUILD_TARGET_OS STREQUAL "Linux")
    list(APPEND SOURCES
        platform/linux/ioctl.cpp
        platform/linux/ioctl_private.cpp
    )
    include_directories(platform/linux/)
elseif(BUILD_TARGET_OS STREQUAL "Windows")
    list(APPEND SOURCES
        platform/windows/ioctl.cpp
        platform/windows/ioctl_private.cpp
    )
    include_directories(platform/windows/)
else()
    message(FATAL_ERROR "Unsupported OS: ${BUILD_TARGET_OS}")
endif()

list(APPEND SOURCES
    command_line_parser.cpp
    ioctl_driver.cpp
    main.cpp
)

add_executable(bfm ${SOURCES})
target_compile_definitions(bfm PUBLIC MAIN=main)
target_compile_definitions(bfm PUBLIC ABORT=abort)

if(CYGWIN OR WIN32)
    target_link_libraries(bfm setupapi)
endif()

install(TARGETS bfm DESTINATION bin)
