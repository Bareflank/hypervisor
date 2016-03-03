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

NATIVE_LDFLAGS+=-u _Unwind_RaiseException
NATIVE_LDFLAGS+=-u _Unwind_Resume
NATIVE_LDFLAGS+=-u _Unwind_DeleteException
NATIVE_LDFLAGS+=-u _Unwind_GetGR
NATIVE_LDFLAGS+=-u _Unwind_SetGR
NATIVE_LDFLAGS+=-u _Unwind_GetIP
NATIVE_LDFLAGS+=-u _Unwind_SetIP
NATIVE_LDFLAGS+=-u _Unwind_GetLanguageSpecificData
NATIVE_LDFLAGS+=-u _Unwind_GetRegionStart
NATIVE_LDFLAGS+=-u _Unwind_GetIPInfo

NATIVE_LDFLAGS+=-static-libstdc++


################################################################################
# Output
################################################################################

NATIVE_OBJDIR:=.build
NATIVE_OUTDIR:=../bin

################################################################################
# Sources
################################################################################

SOURCES+=test.cpp
SOURCES+=../../bfelf_loader/src/bfelf_loader.c
SOURCES+=test_try_catch.cpp

INCLUDE_PATHS+=./
INCLUDE_PATHS+=../include/
INCLUDE_PATHS+=../../include/
INCLUDE_PATHS+=../../bfelf_loader/include/

LIBS+=bfunwind_static

LIBRARY_PATHS+=../bin/native/

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

include ../../common/common_target.mk
