################################################################################
# Auto Generated Section (created by configured script)
################################################################################

HYPER_ABS:=/home/user/hypervisor
BUILD_ABS:=/home/user/hypervisor
HYPER_REL:=/home/user/hypervisor/bfm/main
BUILD_REL:=/home/user/hypervisor/makefiles/bfm/main
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
 
TARGET_NAME:=bfm
TARGET_TYPE:=bin
TARGET_COMPILER:=native
 
################################################################################
# Compiler Flags
################################################################################
 
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
 
NATIVE_OBJDIR+=/home/user/hypervisor/makefiles/bfm/main/.build
NATIVE_OUTDIR+=/home/user/hypervisor/makefiles/bfm/main/../bin
 
################################################################################
# Sources
################################################################################
 
SOURCES+=/home/user/hypervisor/bfm/main/main.cpp
 
INCLUDE_PATHS+=/home/user/hypervisor/bfm/main/./
INCLUDE_PATHS+=/home/user/hypervisor/bfm/main/../include/
INCLUDE_PATHS+=/home/user/hypervisor/include/
 
LIBS+=bfm_static
LIBS+=bfm_ioctl_static
 
LIBRARY_PATHS+=/home/user/hypervisor/makefiles/bfm/main/../bin/native/
 
################################################################################
# Environment Specific
################################################################################
 
WINDOWS_LIBS+=setupapi
################################################################################
# Common
################################################################################
 
include /home/user/hypervisor/common/common_target.mk
