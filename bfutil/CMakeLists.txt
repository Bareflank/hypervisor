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
project(bfutil C CXX)

get_cmake_property(_vars CACHE_VARIABLES)
foreach (_var ${_vars})
    set(${_var} ${${_var}})
endforeach()

message(STATUS "PKG LIST from bfutil: ${PACKAGE_LIST}")

if(CMAKE_INSTALL_PREFIX STREQUAL "${VMM_PREFIX_PATH}")
    set(PREFIX "vmm")
elseif(CMAKE_INSTALL_PREFIX STREQUAL "${USERSPACE_PREFIX_PATH}")
    set(PREFIX "userspace")
elseif(CMAKE_INSTALL_PREFIX STREQUAL "${TEST_PREFIX_PATH}")
    set(PREFIX "test")
elseif(CMAKE_INSTALL_PREFIX STREQUAL "${EFI_PREFIX_PATH}")
    set(PREFIX "efi")
else()
    message(FATAL_ERROR "Invalid prefix: ${CMAKE_INSTALL_PREFIX}")
endif()

set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_EXTENSIONS OFF)
enable_asm(${PREFIX})

add_library(bfutil INTERFACE)
target_link_libraries(bfutil INTERFACE bfroot_${PREFIX})

if(PREFIX STREQUAL "vmm")
    set(CMAKE_SKIP_RPATH TRUE)
endif()

if(PREFIX STREQUAL "test")
    set(ENABLE_MOCKING ON)
    set(CMAKE_BUILD_TYPE "Debug")
endif()

install(DIRECTORY include/ DESTINATION include)
fini_project()
