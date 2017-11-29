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

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

if(NOT WIN32)
    add_custom_command(OUTPUT bfvmcall_intel_x64.o
        COMMAND ${CMAKE_ASM_NASM_COMPILER} ${CMAKE_ASM_NASM_FLAGS} ${CMAKE_CURRENT_LIST_DIR}/bfvmcall_intel_x64.asm -f elf64 -o bfvmcall_intel_x64.o
        DEPENDS ${CMAKE_CURRENT_LIST_DIR}/bfvmcall_intel_x64.asm
    )
    add_executable(bfm main.cpp $<TARGET_OBJECTS:bfm_src> $<TARGET_OBJECTS:bfm_ioctl> bfvmcall_intel_x64.o)
else()
    add_custom_command(OUTPUT bfvmcall_intel_x64.obj
        COMMAND ${CMAKE_ASM_NASM_COMPILER} ${CMAKE_ASM_NASM_FLAGS} ${CMAKE_CURRENT_LIST_DIR}/bfvmcall_intel_x64.asm -f win64 -o bfvmcall_intel_x64.obj
        DEPENDS ${CMAKE_CURRENT_LIST_DIR}/bfvmcall_intel_x64.asm
    )
    add_executable(bfm main.cpp $<TARGET_OBJECTS:bfm_src> $<TARGET_OBJECTS:bfm_ioctl> bfvmcall_intel_x64.obj)
endif()

add_library(bfm_static STATIC main.cpp $<TARGET_OBJECTS:bfm_src> $<TARGET_OBJECTS:bfm_ioctl>)

target_compile_definitions(bfm PUBLIC STATIC_BFM_SRC)
target_compile_definitions(bfm PUBLIC STATIC_BFM_IOCTL)
target_compile_definitions(bfm PUBLIC MAIN=main)
target_compile_definitions(bfm PUBLIC ABORT=abort)

target_compile_definitions(bfm_static PUBLIC STATIC_BFM_SRC)
target_compile_definitions(bfm_static PUBLIC STATIC_BFM_IOCTL)

if(CYGWIN OR WIN32)
    target_link_libraries(bfm setupapi)
    target_link_libraries(bfm_static setupapi)
endif()

install(TARGETS bfm DESTINATION ${BUILD_SYSROOT_OS}/bin)
install(TARGETS bfm_static DESTINATION ${BUILD_SYSROOT_OS}/lib)
