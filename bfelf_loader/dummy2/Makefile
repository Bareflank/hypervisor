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
# Cross Flags
################################################################################

CROSS_CC=~/opt/cross/bin/x86_64-elf-gcc
CROSS_CXX=~/opt/cross/bin/x86_64-elf-g++
CROSS_ASM=~/opt/cross/bin/nasm
CROSS_LD=~/opt/cross/bin/x86_64-elf-ld

CROSS_CCFLAGS=
CROSS_CXXFLAGS=-std=c++14
CROSS_ASMFLAGS=-f elf64
CROSS_LDFLAGS=

CROSS_DEFINES=

CROSS_OBJDIR=.build/cross
CROSS_OUTDIR=../bin/cross

################################################################################
# Common
################################################################################

RM=rm -rf
MD=mkdir -p

################################################################################
# Sources
################################################################################

TARGET_NAME=dummy2
TARGET_TYPE=lib
TARGET_COMPILER=cross

SOURCES=dummy2.cpp
HEADERS=

LIBS=

LIB_PATHS=
INCLUDE_PATHS=./ ../include/

################################################################################
# Environment Specific
################################################################################

VMM_SOURCES=
VMM_INCLUDE_PATHS=

WINDOWS_SOURCES=
WINDOWS_INCLUDE_PATHS=

LINUX_SOURCES=
LINUX_INCLUDE_PATHS=

OSX_SOURCES=
OSX_INCLUDE_PATHS=

################################################################################
# Common
################################################################################

include ../../common/common_target.mk
