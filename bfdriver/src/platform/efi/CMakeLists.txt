#
# Bareflank Hypervisor
# Copyright (C) 2018 Assured Information Security, Inc.
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
project(efi_main C CXX)

include(${SOURCE_CMAKE_DIR}/project.cmake)
init_project(
    INCLUDES ${VMM_PREFIX_PATH}/include
    INCLUDES ${VMM_PREFIX_PATH}/include/efi
    INCLUDES ${VMM_PREFIX_PATH}/include/efi/${BUILD_TARGET_ARCH}
    INCLUDES ${EFI_OUTPUT_DIR}
    INCLUDES ${SOURCE_BFDRIVER_DIR}/include
    INCLUDES ${SOURCE_BFDRIVER_DIR}/src/platform/efi/efi_main
    INCLUDES ${SOURCE_BFELF_LOADER_DIR}/include
    INCLUDES ${SOURCE_BFSDK_DIR}/include
)

add_subdirectory(efi_main)
