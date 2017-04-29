################################################################################
# Auto Generated Section (created by configured script)
################################################################################

HYPER_ABS:=/home/user/hypervisor
BUILD_ABS:=/home/user/hypervisor
HYPER_REL:=/home/user/hypervisor/bfvmm/src/vcpu/test
BUILD_REL:=/home/user/hypervisor/makefiles/bfvmm/src/vcpu/test
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
 
TARGET_NAME:=test
TARGET_TYPE:=bin
TARGET_COMPILER:=native
 
################################################################################
# Compiler Flags
################################################################################
 
NATIVE_CXXFLAGS+=-Wno-unused-result
################################################################################
# Output
################################################################################
 
NATIVE_OBJDIR+=/home/user/hypervisor/makefiles/bfvmm/src/vcpu/test/.build
NATIVE_OUTDIR+=/home/user/hypervisor/makefiles/bfvmm/src/vcpu/test/../bin
 
################################################################################
# Sources
################################################################################
 
SOURCES+=/home/user/hypervisor/bfvmm/src/vcpu/test/test.cpp
SOURCES+=/home/user/hypervisor/bfvmm/src/vcpu/test/test_vcpu.cpp
SOURCES+=/home/user/hypervisor/bfvmm/src/vcpu/test/test_vcpu_intel_x64.cpp
SOURCES+=/home/user/hypervisor/bfvmm/src/vcpu/test/test_vcpu_manager.cpp
 
INCLUDE_PATHS+=/home/user/hypervisor/bfvmm/src/vcpu/test/./
INCLUDE_PATHS+=/home/user/hypervisor/include/
INCLUDE_PATHS+=/home/user/hypervisor/bfvmm/include/
 
LIBS+=vcpu
LIBS+=vcpu_factory
LIBS+=vmxon
LIBS+=vmcs
LIBS+=debug_ring
LIBS+=intrinsics
LIBS+=exit_handler
LIBS+=memory_manager
 
LIBRARY_PATHS+=/home/user/hypervisor/makefiles/bfvmm/src/vcpu/test/../bin/native
LIBRARY_PATHS+=/home/user/hypervisor/makefiles/bfvmm/src/vcpu/test/../../vcpu_factory/bin/native
LIBRARY_PATHS+=/home/user/hypervisor/makefiles/bfvmm/src/vcpu/test/../../vmxon/bin/native
LIBRARY_PATHS+=/home/user/hypervisor/makefiles/bfvmm/src/vcpu/test/../../vmcs/bin/native
LIBRARY_PATHS+=/home/user/hypervisor/makefiles/bfvmm/src/vcpu/test/../../debug_ring/bin/native
LIBRARY_PATHS+=/home/user/hypervisor/makefiles/bfvmm/src/vcpu/test/../../intrinsics/bin/native
LIBRARY_PATHS+=/home/user/hypervisor/makefiles/bfvmm/src/vcpu/test/../../exit_handler/bin/native
LIBRARY_PATHS+=/home/user/hypervisor/makefiles/bfvmm/src/vcpu/test/../../memory_manager/bin/native
 
################################################################################
# Environment Specific
################################################################################
 
################################################################################
# Common
################################################################################
 
include /home/user/hypervisor/common/common_target.mk
