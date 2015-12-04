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
# Native Flags
################################################################################

CC=gcc
CXX=g++
ASM=nasm
LD=g++

CCFLAGS=
CXXFLAGS=-std=c++14
ASMFLAGS=
LDFLAGS=

DEFINES=

OBJDIR=.build/native
OUTDIR=../bin/native

################################################################################
# Common
################################################################################

RM=rm -rf
MD=mkdir -p

################################################################################
# Sources
################################################################################

TARGET_NAME=bfm
TARGET_TYPE=lib
TARGET_COMPILER=native

SOURCES+=command_line_parser.cpp
SOURCES+=debug.cpp
SOURCES+=file.cpp
SOURCES+=ioctl_driver.cpp
SOURCES+=split.cpp
HEADERS=

LIBS=

LIB_PATHS=
INCLUDE_PATHS=./ ../include/ ../../include/

VPATH=arch/linux

################################################################################
# Environment Specific
################################################################################

VMM_SOURCES=
VMM_INCLUDE_PATHS=

WINDOWS_SOURCES=
WINDOWS_INCLUDE_PATHS=

LINUX_SOURCES+=ioctl.cpp
LINUX_SOURCES+=ioctl_private.cpp
LINUX_INCLUDE_PATHS+=./arch/linux/

OSX_SOURCES=
OSX_INCLUDE_PATHS=

################################################################################
# Common
################################################################################

include ../../common/common_target.mk
