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

cmake_minimum_required(VERSION 3.13)
project(bfdriver C CXX)

init_project(bfdriver INTERFACE)
target_link_libraries(bfdriver INTERFACE ${PREFIX}::bfroot)

# ------------------------------------------------------------------------------
# Generator expressions
# ------------------------------------------------------------------------------

set(C $<COMPILE_LANGUAGE:C>)
set(CXX $<COMPILE_LANGUAGE:CXX>)
set(BUILD $<BOOL:$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>>)
set(BUILD_INCLUDE $<AND:$<OR:${C},${CXX}>,${BUILD}>)
set(BUILD_INCLUDE_CXX $<AND:${CXX},${BUILD}>)

# ------------------------------------------------------------------------------
# EFI
# ------------------------------------------------------------------------------

if(${PREFIX} STREQUAL efi)
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

    add_library(bareflank SHARED)
    add_dependencies(bareflank bareflank_xxd)

    target_link_libraries(bareflank PRIVATE bfdriver)
    target_include_directories(bareflank PRIVATE
        $<${BUILD_INCLUDE}:${CMAKE_CURRENT_LIST_DIR}/include>
        $<${BUILD_INCLUDE}:${CMAKE_CURRENT_LIST_DIR}/../bfsdk/include>
        $<${BUILD_INCLUDE}:${CMAKE_BINARY_DIR}>
    )
    target_sources(bareflank PRIVATE
        src/platform/efi/entry.c
        src/platform/efi/platform.c
        src/platform/efi/platform.asm
        src/common.c
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
endif()

# ------------------------------------------------------------------------------
# Test
# ------------------------------------------------------------------------------

if(${PREFIX} STREQUAL test)
    target_include_directories(bfdriver INTERFACE
        $<${BUILD_INCLUDE}:${CMAKE_CURRENT_LIST_DIR}/include>
        $<${BUILD_INCLUDE}:${CMAKE_CURRENT_LIST_DIR}/../bfsdk/include>
    )
    target_compile_definitions(bfdriver INTERFACE
        $<${BUILD_INCLUDE_CXX}:VMM_PREFIX_PATH=\"${VMM_PREFIX_PATH}\">
    )
    add_library(support)
    target_link_libraries(support PRIVATE bfdriver)
    target_sources(support PRIVATE
        tests/test_support.cpp
        src/common.c
        src/platform/test/platform.c
    )
endif()

fini_project()
