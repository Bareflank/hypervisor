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

TARGET_NAME:=misc
TARGET_TYPE:=bin
TARGET_COMPILER:=cross

################################################################################
# Compiler Flags
################################################################################

CROSS_CCFLAGS+=
CROSS_CXXFLAGS+=
CROSS_ASMFLAGS+=
CROSS_LDFLAGS+=--export-dynamic -pie -Wl
CROSS_ARFLAGS+=
CROSS_DEFINES+=

ifeq ($(OS), Windows_NT)
    CROSS_ASMFLAGS+=-d MS64
endif

################################################################################
# Output
################################################################################

CROSS_OBJDIR+=%BUILD_REL%/.build
CROSS_OUTDIR+=%BUILD_REL%/../bin

################################################################################
# Sources
################################################################################

SOURCES+=misc.cpp
SOURCES+=misc_all.cpp
#SOURCES+=misc_no_hyper.cpp
#SOURCES+=misc_no_hyper_or_libcxx.cpp
SOURCES+=execute_entry_x64.asm

INCLUDE_PATHS+=./
INCLUDE_PATHS+=%HYPER_ABS%/include/
INCLUDE_PATHS+=%HYPER_ABS%/bfvmm/include/

LIBS+=vmcs
LIBS+=exit_handler
LIBS+=vcpu
LIBS+=vcpu_factory
LIBS+=vmxon
LIBS+=debug_ring
LIBS+=intrinsics
LIBS+=memory_manager
LIBS+=serial
LIBS+=pthread
LIBS+=syscall
LIBS+=bfunwind

LIBRARY_PATHS+=%BUILD_REL%/../bin/cross
LIBRARY_PATHS+=%BUILD_REL%/../../vmcs/bin/cross
LIBRARY_PATHS+=%BUILD_REL%/../../exit_handler/bin/cross
LIBRARY_PATHS+=%BUILD_REL%/../../vcpu/bin/cross
LIBRARY_PATHS+=%BUILD_REL%/../../vcpu_factory/bin/cross
LIBRARY_PATHS+=%BUILD_REL%/../../vmxon/bin/cross
LIBRARY_PATHS+=%BUILD_REL%/../../debug_ring/bin/cross
LIBRARY_PATHS+=%BUILD_REL%/../../intrinsics/bin/cross
LIBRARY_PATHS+=%BUILD_REL%/../../memory_manager/bin/cross
LIBRARY_PATHS+=%BUILD_REL%/../../serial/bin/cross
LIBRARY_PATHS+=%BUILD_REL%/../../pthread/bin/cross
LIBRARY_PATHS+=%BUILD_REL%/../../syscall/bin/cross
LIBRARY_PATHS+=%BUILD_ABS%/makefiles/bfunwind/bin/cross/

################################################################################
# Environment Specific
################################################################################

VMM_SOURCES+=
VMM_INCLUDE_PATHS+=
VMM_LIBS+=
VMM_LIBRARY_PATHS+=

WINDOWS_SOURCES+=
WINDOWS_INCLUDE_PATHS+=
WINDOWS_LIBS+=
WINDOWS_LIBRARY_PATHS+=

LINUX_SOURCES+=
LINUX_INCLUDE_PATHS+=
LINUX_LIBS+=
LINUX_LIBRARY_PATHS+=

################################################################################
# Common
################################################################################

include %HYPER_ABS%/common/common_target.mk
