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
project(bfsupport C CXX)

set(TIDY_EXCLUSIONS ,-cert-err34-c,-misc-misplaced-widening-cast,-cppcoreguidelines-no-malloc)
include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Project.txt)

# ------------------------------------------------------------------------------
# Flags
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNOSTDLIB_C")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DNOSTDLIB_C -DNOSTDLIB_CXX")
endif()

# ------------------------------------------------------------------------------
# Subdirectories
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    set(INSTALL_LIB_DIR ${BAREFLANK_SYSROOT_PATH}/lib)
    set(INSTALL_BIN_DIR ${BAREFLANK_SYSROOT_PATH}/bin)
else()
    set(INSTALL_LIB_DIR ${CMAKE_INSTALL_PREFIX}/lib)
    set(INSTALL_BIN_DIR ${CMAKE_INSTALL_PREFIX}/bin)
endif()

add_subdirectory(crt)

if(CMAKE_TOOLCHAIN_FILE)
    add_subdirectory(syscall)
    add_subdirectory(pthread)
    add_subdirectory(dummy_lib1)
    add_subdirectory(dummy_lib2)
    add_subdirectory(dummy_main)
endif()
