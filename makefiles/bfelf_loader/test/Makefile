################################################################################
# Auto Generated Section (created by configured script)
################################################################################

HYPER_ABS:=/home/user/hypervisor
BUILD_ABS:=/home/user/hypervisor
HYPER_REL:=/home/user/hypervisor/bfelf_loader/test
BUILD_REL:=/home/user/hypervisor/makefiles/bfelf_loader/test
COMPILER:=clang
LINKER:=ld
CONFIGURED_CROSS_CCFLAGS:= -fpic -fexceptions -mmmx -msse -msse2 -msse3 -mssse3 -msse4.1 -msse4.2 -msse4 -mavx -mno-red-zone -mstackrealign -fstack-protector-strong -std=c99
CONFIGURED_CROSS_CXXFLAGS:= -fpic -fexceptions -mmmx -msse -msse2 -msse3 -mssse3 -msse4.1 -msse4.2 -msse4 -mavx -mno-red-zone -mstackrealign -fstack-protector-strong -std=c++14
CONFIGURED_NATIVE_CCFLAGS:= -fpic -fexceptions -mmmx -msse -msse2 -msse3 -mssse3 -msse4.1 -msse4.2 -msse4 -mavx -std=c99
CONFIGURED_NATIVE_CXXFLAGS:= -fpic -fexceptions -mmmx -msse -msse2 -msse3 -mssse3 -msse4.1 -msse4.2 -msse4 -mavx -std=c++14
MAKEFILE_ABS:=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))
ifneq ($(dir $(BUILD_REL)/), $(MAKEFILE_ABS))
    $(error Build system has moved which is not supported!!!)
endif


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
 
################################################################################
# Output
################################################################################
 
NATIVE_OBJDIR+=/home/user/hypervisor/makefiles/bfelf_loader/test/.build
NATIVE_OUTDIR+=/home/user/hypervisor/makefiles/bfelf_loader/test/../bin
 
################################################################################
# Sources
################################################################################
 
SOURCES+=/home/user/hypervisor/bfelf_loader/test/test.cpp
SOURCES+=/home/user/hypervisor/bfelf_loader/test/test_file_init.cpp
SOURCES+=/home/user/hypervisor/bfelf_loader/test/test_file_get_num_load_instrs.cpp
SOURCES+=/home/user/hypervisor/bfelf_loader/test/test_file_get_load_instr.cpp
SOURCES+=/home/user/hypervisor/bfelf_loader/test/test_loader_add.cpp
SOURCES+=/home/user/hypervisor/bfelf_loader/test/test_loader_relocate.cpp
SOURCES+=/home/user/hypervisor/bfelf_loader/test/test_file_get_section_info.cpp
SOURCES+=/home/user/hypervisor/bfelf_loader/test/test_loader_resolve_symbol.cpp
SOURCES+=/home/user/hypervisor/bfelf_loader/test/test_file_get_entry.cpp
SOURCES+=/home/user/hypervisor/bfelf_loader/test/test_file_get_stack_perm.cpp
SOURCES+=/home/user/hypervisor/bfelf_loader/test/test_file_get_relro.cpp
SOURCES+=/home/user/hypervisor/bfelf_loader/test/test_file_get_num_needed.cpp
SOURCES+=/home/user/hypervisor/bfelf_loader/test/test_file_get_needed.cpp
SOURCES+=/home/user/hypervisor/bfelf_loader/test/test_file_get_total_size.cpp
SOURCES+=/home/user/hypervisor/bfelf_loader/test/test_file_get_pic_pie.cpp
SOURCES+=/home/user/hypervisor/bfelf_loader/test/test_private.cpp
 
INCLUDE_PATHS+=/home/user/hypervisor/bfelf_loader/test/./
INCLUDE_PATHS+=/home/user/hypervisor/bfelf_loader/test/../include/
INCLUDE_PATHS+=/home/user/hypervisor/include/
 
LIBRARY_PATHS+=/home/user/hypervisor/makefiles/bfelf_loader/test/../bin/native/
 
################################################################################
# Environment Specific
################################################################################
 
################################################################################
# Common
################################################################################
 
include /home/user/hypervisor/common/common_target.mk
