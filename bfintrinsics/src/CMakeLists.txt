#
# Copyright (C) 2019 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

cmake_minimum_required(VERSION 3.6)
project(bfintrinsics C CXX)

include(${SOURCE_CMAKE_DIR}/project.cmake)
init_project()

list(APPEND SOURCES
    null.cpp
)

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
        arch/intel_x64/barrier.asm
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

add_static_library(
    bfintrinsics
    SOURCES ${SOURCES}
    DEFINES STATIC_INTRINSICS
    ALWAYS
)
