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

TARGET_NAME:=bfm
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

ifeq ($(OS), windows)
    NATIVE_DEFINES+=-Wl,--enable-auto-import
endif

ifeq ($(PRODUCTION),yes)
    NATIVE_CCFLAGS+=-O3 -D_FORTIFY_SOURCE=2
    NATIVE_CXXFLAGS+=-O3 -D_FORTIFY_SOURCE=2
endif

################################################################################
# Output
################################################################################

NATIVE_OBJDIR+=%BUILD_REL%/.build
NATIVE_OUTDIR+=%BUILD_REL%/../bin

################################################################################
# Sources
################################################################################

SOURCES+=main.cpp

INCLUDE_PATHS+=./
INCLUDE_PATHS+=../include/
INCLUDE_PATHS+=%HYPER_ABS%/include/

LIBS+=bfm_static
LIBS+=bfm_ioctl_static

LIBRARY_PATHS+=%BUILD_REL%/../bin/native/

################################################################################
# Environment Specific
################################################################################

WINDOWS_SOURCES+=
WINDOWS_INCLUDE_PATHS+=
WINDOWS_LIBS+=setupapi
WINDOWS_LIBRARY_PATHS+=

LINUX_SOURCES+=
LINUX_INCLUDE_PATHS+=
LINUX_LIBS+=
LINUX_LIBRARY_PATHS+=

################################################################################
# Common
################################################################################

include %HYPER_ABS%/common/common_target.mk
