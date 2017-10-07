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
project(bfvmm C CXX)

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Project.txt)

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

if(NOT CMAKE_TOOLCHAIN_FILE)
    if(NOT CMAKE_TOOLCHAIN_FILE)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DDEBUG_LEVEL=1")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DDEBUG_LEVEL=1")
    endif()
endif()

add_subdirectory(src)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(DIRECTORY include/debug_ring DESTINATION include)
install(DIRECTORY include/exit_handler DESTINATION include)
install(DIRECTORY include/intrinsics DESTINATION include)
install(DIRECTORY include/memory_manager DESTINATION include)
install(DIRECTORY include/serial DESTINATION include)
install(DIRECTORY include/vcpu DESTINATION include)
install(DIRECTORY include/vmcs DESTINATION include)
install(DIRECTORY include/vmxon DESTINATION include)
install(FILES include/user_data.h DESTINATION include)
