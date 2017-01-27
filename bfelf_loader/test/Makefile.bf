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

NO_ADDRESS_SANATIZE:=true

################################################################################
# Target Information
################################################################################

TARGET_NAME:=test
TARGET_TYPE:=bin
TARGET_COMPILER:=native
PRODUCTION=no

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
SOURCES+=test_file_init.cpp
SOURCES+=test_file_num_load_instrs.cpp
SOURCES+=test_file_get_load_instr.cpp
SOURCES+=test_file_resolve_symbol.cpp
SOURCES+=test_loader_add.cpp
SOURCES+=test_loader_relocate.cpp
SOURCES+=test_file_get_section_info.cpp
SOURCES+=test_loader_resolve_symbol.cpp
SOURCES+=test_file_get_entry.cpp
SOURCES+=test_file_get_stack_perm.cpp
SOURCES+=test_file_get_relro.cpp
SOURCES+=test_file_get_num_needed.cpp
SOURCES+=test_file_get_needed.cpp
SOURCES+=test_file_get_total_size.cpp
SOURCES+=test_file_get_pic_pie.cpp
SOURCES+=test_private.cpp

INCLUDE_PATHS+=./
INCLUDE_PATHS+=../include/
INCLUDE_PATHS+=%HYPER_ABS%/include/

LIBS+=bfelf_loader

LIBRARY_PATHS+=%BUILD_REL%/../bin/native/

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
