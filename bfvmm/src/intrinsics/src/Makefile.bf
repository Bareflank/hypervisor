#
# Bareflank Hypervisor
#
# Copyright (C) 2015 Assured Information Security, Inc.
# Author: Rian Quinn        <quinnr@ainfosec.com>
# Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

################################################################################
# Target Information
################################################################################

TARGET_NAME:=intrinsics
TARGET_TYPE:=lib

ifeq ($(shell uname -s), Linux)
    TARGET_COMPILER:=both
else
    TARGET_COMPILER:=cross
endif

################################################################################
# Compiler Flags
################################################################################

NATIVE_CCFLAGS+=
NATIVE_CXXFLAGS+=
NATIVE_ASMFLAGS+=
NATIVE_LDFLAGS+=
NATIVE_ARFLAGS+=
NATIVE_DEFINES+=

CROSS_CCFLAGS+=
CROSS_CXXFLAGS+=
CROSS_ASMFLAGS+=
CROSS_LDFLAGS+=
CROSS_ARFLAGS+=
CROSS_DEFINES+=

################################################################################
# Output
################################################################################

CROSS_OBJDIR+=%BUILD_REL%/.build
CROSS_OUTDIR+=%BUILD_REL%/../bin

NATIVE_OBJDIR+=%BUILD_REL%/.build
NATIVE_OUTDIR+=%BUILD_REL%/../bin

################################################################################
# Sources
################################################################################

INCLUDE_PATHS+=./
INCLUDE_PATHS+=%HYPER_ABS%/include/
INCLUDE_PATHS+=%HYPER_ABS%/bfvmm/include/

LIBS+=

LIBRARY_PATHS+=

################################################################################
# Environment Specific
################################################################################

VMM_SOURCES+=cache_x64.asm
VMM_SOURCES+=cpuid_x64.asm
VMM_SOURCES+=crs_intel_x64.asm
VMM_SOURCES+=debug_x64.asm
VMM_SOURCES+=gdt_x64.asm
VMM_SOURCES+=idt_x64.asm
VMM_SOURCES+=msrs_intel_x64.asm
VMM_SOURCES+=pm_x64.asm
VMM_SOURCES+=portio_x64.asm
VMM_SOURCES+=rdtsc_x64.asm
VMM_SOURCES+=rflags_x64.asm
VMM_SOURCES+=srs_x64.asm
VMM_SOURCES+=tlb_x64.asm
VMM_SOURCES+=vmx_intel_x64.asm
VMM_SOURCES+=thread_context_x64.asm
VMM_INCLUDE_PATHS+=
VMM_LIBS+=
VMM_LIBRARY_PATHS+=

WINDOWS_SOURCES+=
WINDOWS_INCLUDE_PATHS+=
WINDOWS_LIBS+=
WINDOWS_LIBRARY_PATHS+=

LINUX_SOURCES+=cache_x64_mock.cpp
LINUX_SOURCES+=cpuid_x64_mock.cpp
LINUX_SOURCES+=crs_intel_x64_mock.cpp
LINUX_SOURCES+=debug_x64_mock.cpp
LINUX_SOURCES+=gdt_x64_mock.cpp
LINUX_SOURCES+=idt_x64_mock.cpp
LINUX_SOURCES+=msrs_intel_x64_mock.cpp
LINUX_SOURCES+=pm_x64_mock.cpp
LINUX_SOURCES+=portio_x64_mock.cpp
LINUX_SOURCES+=rdtsc_x64_mock.cpp
LINUX_SOURCES+=rflags_x64_mock.cpp
LINUX_SOURCES+=srs_x64_mock.cpp
LINUX_SOURCES+=tlb_x64_mock.cpp
LINUX_SOURCES+=vmx_intel_x64_mock.cpp
LINUX_SOURCES+=thread_context_x64_mock.cpp
LINUX_INCLUDE_PATHS+=
LINUX_LIBS+=
LINUX_LIBRARY_PATHS+=

################################################################################
# Common
################################################################################

include %HYPER_ABS%/common/common_target.mk
