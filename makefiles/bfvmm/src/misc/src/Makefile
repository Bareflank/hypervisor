################################################################################
# Auto Generated Section (created by configured script)
################################################################################

HYPER_ABS:=/home/user/hypervisor
BUILD_ABS:=/home/user/hypervisor
HYPER_REL:=/home/user/hypervisor/bfvmm/src/misc/src
BUILD_REL:=/home/user/hypervisor/makefiles/bfvmm/src/misc/src
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
 
TARGET_NAME:=misc
TARGET_TYPE:=bin
TARGET_COMPILER:=cross
 
################################################################################
# Compiler Flags
################################################################################
 
CROSS_LDFLAGS+=--export-dynamic -pie -Wl
ifeq ($(OS), Windows_NT)
    CROSS_ASMFLAGS+=-d MS64
endif
 
################################################################################
# Output
################################################################################
 
CROSS_OBJDIR+=/home/user/hypervisor/makefiles/bfvmm/src/misc/src/.build
CROSS_OUTDIR+=/home/user/hypervisor/makefiles/bfvmm/src/misc/src/../bin
 
################################################################################
# Sources
################################################################################
 
SOURCES+=/home/user/hypervisor/bfvmm/src/misc/src/misc.cpp
SOURCES+=/home/user/hypervisor/bfvmm/src/misc/src/misc_all.cpp
#SOURCES+=/home/user/hypervisor/bfvmm/src/misc/src/misc_no_hyper.cpp
#SOURCES+=/home/user/hypervisor/bfvmm/src/misc/src/misc_no_hyper_or_libcxx.cpp
SOURCES+=/home/user/hypervisor/bfvmm/src/misc/src/execute_entry_x64.asm
 
INCLUDE_PATHS+=/home/user/hypervisor/bfvmm/src/misc/src/./
INCLUDE_PATHS+=/home/user/hypervisor/include/
INCLUDE_PATHS+=/home/user/hypervisor/bfvmm/include/
 
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
 
LIBRARY_PATHS+=/home/user/hypervisor/makefiles/bfvmm/src/misc/src/../bin/cross
LIBRARY_PATHS+=/home/user/hypervisor/makefiles/bfvmm/src/misc/src/../../vmcs/bin/cross
LIBRARY_PATHS+=/home/user/hypervisor/makefiles/bfvmm/src/misc/src/../../exit_handler/bin/cross
LIBRARY_PATHS+=/home/user/hypervisor/makefiles/bfvmm/src/misc/src/../../vcpu/bin/cross
LIBRARY_PATHS+=/home/user/hypervisor/makefiles/bfvmm/src/misc/src/../../vcpu_factory/bin/cross
LIBRARY_PATHS+=/home/user/hypervisor/makefiles/bfvmm/src/misc/src/../../vmxon/bin/cross
LIBRARY_PATHS+=/home/user/hypervisor/makefiles/bfvmm/src/misc/src/../../debug_ring/bin/cross
LIBRARY_PATHS+=/home/user/hypervisor/makefiles/bfvmm/src/misc/src/../../intrinsics/bin/cross
LIBRARY_PATHS+=/home/user/hypervisor/makefiles/bfvmm/src/misc/src/../../memory_manager/bin/cross
LIBRARY_PATHS+=/home/user/hypervisor/makefiles/bfvmm/src/misc/src/../../serial/bin/cross
LIBRARY_PATHS+=/home/user/hypervisor/makefiles/bfvmm/src/misc/src/../../pthread/bin/cross
LIBRARY_PATHS+=/home/user/hypervisor/makefiles/bfvmm/src/misc/src/../../syscall/bin/cross
LIBRARY_PATHS+=/home/user/hypervisor/makefiles/bfunwind/bin/cross/
 
################################################################################
# Environment Specific
################################################################################
 
################################################################################
# Common
################################################################################
 
include /home/user/hypervisor/common/common_target.mk
