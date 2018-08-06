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
project(bfintrinsics C CXX)

include(${SOURCE_CMAKE_DIR}/project.cmake)
init_project()

if(${BUILD_TARGET_ARCH} STREQUAL "x86_64")
    list(APPEND SOURCES
        arch/x64/cache.asm
        arch/x64/cpuid.asm
        arch/x64/gdt.asm
        arch/x64/idt.asm
        arch/x64/msrs.asm
        arch/x64/pm.asm
        arch/x64/portio.asm
        arch/x64/rdtsc.asm
        arch/x64/rflags.asm
        arch/x64/srs.asm
        arch/x64/tlb.asm
        arch/intel_x64/bit.asm
        arch/intel_x64/crs.asm
        arch/intel_x64/drs.asm
        arch/intel_x64/pause.asm
        arch/intel_x64/vmx.asm
    )
elseif(${BUILD_TARGET_ARCH} STREQUAL "aarch64")
    message(WARNING "Unimplemented")
else()
    message(FATAL_ERROR "Unsupported archiecture")
endif()

add_shared_library(
    bfintrinsics
    SOURCES ${SOURCES}
    DEFINES SHARED_INTRINSICS
    ALWAYS
)

add_static_library(
    bfintrinsics
    SOURCES ${SOURCES}
    DEFINES STATIC_INTRINSICS
    ALWAYS
)
