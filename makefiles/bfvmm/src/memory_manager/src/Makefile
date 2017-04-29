################################################################################
# Auto Generated Section (created by configured script)
################################################################################

HYPER_ABS:=/home/user/hypervisor
BUILD_ABS:=/home/user/hypervisor
HYPER_REL:=/home/user/hypervisor/bfvmm/src/memory_manager/src
BUILD_REL:=/home/user/hypervisor/makefiles/bfvmm/src/memory_manager/src
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
 
################################################################################
# Target Information
################################################################################
 
TARGET_NAME:=memory_manager
TARGET_TYPE:=lib
 
ifeq ($(shell uname -s), Linux)
    TARGET_COMPILER:=both
else
    TARGET_COMPILER:=cross
endif
 
################################################################################
# Compiler Flags
################################################################################
 
################################################################################
# Output
################################################################################
 
CROSS_OBJDIR+=/home/user/hypervisor/makefiles/bfvmm/src/memory_manager/src/.build
CROSS_OUTDIR+=/home/user/hypervisor/makefiles/bfvmm/src/memory_manager/src/../bin
 
NATIVE_OBJDIR+=/home/user/hypervisor/makefiles/bfvmm/src/memory_manager/src/.build
NATIVE_OUTDIR+=/home/user/hypervisor/makefiles/bfvmm/src/memory_manager/src/../bin
 
################################################################################
# Sources
################################################################################
 
SOURCES+=/home/user/hypervisor/bfvmm/src/memory_manager/src/map_ptr_x64.cpp
SOURCES+=/home/user/hypervisor/bfvmm/src/memory_manager/src/memory_manager_x64.cpp
SOURCES+=/home/user/hypervisor/bfvmm/src/memory_manager/src/page_table_x64.cpp
SOURCES+=/home/user/hypervisor/bfvmm/src/memory_manager/src/page_table_entry_x64.cpp
SOURCES+=/home/user/hypervisor/bfvmm/src/memory_manager/src/root_page_table_x64.cpp
HEADERS=
 
INCLUDE_PATHS+=/home/user/hypervisor/bfvmm/src/memory_manager/src/./
INCLUDE_PATHS+=/home/user/hypervisor/include/
INCLUDE_PATHS+=/home/user/hypervisor/bfvmm/include/
 
################################################################################
# Environment Specific
################################################################################
 
################################################################################
# Common
################################################################################
 
include /home/user/hypervisor/common/common_target.mk
