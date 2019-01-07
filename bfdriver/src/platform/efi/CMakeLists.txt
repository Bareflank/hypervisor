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
project(bfefi C CXX)

init_project(bfefi INTERFACE)
target_link_libraries(bfefi INTERFACE efi::bfroot)

# ------------------------------------------------------------------------------
# Generator expressions
# ------------------------------------------------------------------------------

set(C $<COMPILE_LANGUAGE:C>)
set(BUILD $<BOOL:$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>>)
set(BUILD_INCLUDE $<AND:${C},${BUILD}>)

# ------------------------------------------------------------------------------
# Shellcode command
# ------------------------------------------------------------------------------

add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/vmm.h
    COMMAND ${CMAKE_COMMAND}
    ARGS -E copy ${BFM_VMM_BIN_PATH}/${BFM_VMM} vmm
    COMMAND xxd
    ARGS -i vmm > ${CMAKE_BINARY_DIR}/vmm.h
    DEPENDS ${BFM_VMM_BIN_PATH}/${BFM_VMM}
    COMMENT "  EFI VMM: ${BFM_VMM_BIN_PATH}/${BFM_VMM}"
)
add_custom_target(
    bareflank_xxd
    DEPENDS ${CMAKE_BINARY_DIR}/vmm.h
)

# ------------------------------------------------------------------------------
# EFI application
# ------------------------------------------------------------------------------

add_library(bareflank SHARED)
add_dependencies(bareflank bareflank_xxd)
target_link_libraries(bareflank PRIVATE bfefi)

target_include_directories(bareflank PRIVATE
    $<${BUILD_INCLUDE}:${CMAKE_CURRENT_LIST_DIR}/../../../include>
    $<${BUILD_INCLUDE}:${CMAKE_CURRENT_LIST_DIR}/../../../../bfutil/include>
    $<${BUILD_INCLUDE}:${CMAKE_BINARY_DIR}>
)
target_sources(bareflank PRIVATE
    entry.c
    platform.c
    platform.asm
    ../../../src/common.c
    ${EFI_EXTENSION_SOURCES}
)
add_custom_command(
    TARGET bareflank
    POST_BUILD
    COMMAND ${CMAKE_OBJCOPY}
    ARGS -j .text -j .sdata -j .data -j .dynamic -j .dynsym
    ARGS -j .rel -j .rela -j .rel.* -j .rela.* -j .rel* -j .rela* -j .reloc
    ARGS --target efi-app-${BUILD_TARGET_ARCH} libbareflank.so ${CMAKE_BINARY_DIR}/bareflank.efi
)

install(FILES ${CMAKE_BINARY_DIR}/bareflank.efi DESTINATION bin)
fini_project()
