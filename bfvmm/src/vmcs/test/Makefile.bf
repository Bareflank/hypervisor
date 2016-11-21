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

TARGET_NAME:=test
TARGET_TYPE:=bin
TARGET_COMPILER:=native

################################################################################
# Compiler Flags
################################################################################

NATIVE_CCFLAGS+=
NATIVE_CXXFLAGS+=
NATIVE_ASMFLAGS+=
NATIVE_LDFLAGS+=
NATIVE_ARFLAGS+=
NATIVE_DEFINES+=

################################################################################
# Output
################################################################################

NATIVE_OBJDIR+=%BUILD_REL%/.build
NATIVE_OUTDIR+=%BUILD_REL%/../bin

################################################################################
# Sources
################################################################################

SOURCES+=test.cpp
SOURCES+=test_vmcs_intel_x64.cpp
SOURCES+=test_vmcs_intel_x64_debug.cpp
SOURCES+=test_vmcs_intel_x64_check_controls.cpp
SOURCES+=test_vmcs_intel_x64_check_host.cpp
SOURCES+=test_vmcs_intel_x64_check_guest.cpp

INCLUDE_PATHS+=./
INCLUDE_PATHS+=%HYPER_ABS%/include/
INCLUDE_PATHS+=%HYPER_ABS%/bfvmm/include/

LIBS+=vmcs
LIBS+=exit_handler
LIBS+=vcpu
LIBS+=vcpu_factory
LIBS+=vmxon
LIBS+=vmcs
LIBS+=debug_ring
LIBS+=intrinsics
LIBS+=memory_manager

LIBRARY_PATHS+=%BUILD_REL%/../bin/native
LIBRARY_PATHS+=%BUILD_REL%/../../exit_handler/bin/native
LIBRARY_PATHS+=%BUILD_REL%/../../vcpu/bin/native
LIBRARY_PATHS+=%BUILD_REL%/../../vcpu_factory/bin/native
LIBRARY_PATHS+=%BUILD_REL%/../../vmxon/bin/native
LIBRARY_PATHS+=%BUILD_REL%/../../vmcs/bin/native
LIBRARY_PATHS+=%BUILD_REL%/../../debug_ring/bin/native
LIBRARY_PATHS+=%BUILD_REL%/../../intrinsics/bin/native
LIBRARY_PATHS+=%BUILD_REL%/../../memory_manager/bin/native

################################################################################
# Environment Specific
################################################################################

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
