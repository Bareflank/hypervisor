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
CROSS_CXXFLAGS=
CROSS_LDFLAGS=
CROSS_ASMFLAGS=-f elf64

CROSS_OBJDIR=.build/cross
CROSS_OUTDIR=../../../bin/cross

################################################################################
# Native Flags
################################################################################

CC=gcc
CXX=g++
LD=g++
ASM=nasm

CCFLAGS=
CXXFLAGS=
LDFLAGS=
ASMFLAGS=-f elf64

OBJDIR=.build/native
OUTDIR=../bin/native

################################################################################
# Common
################################################################################

DEFINES=

RM=rm -rf
MD=mkdir -p

################################################################################
# Sources
################################################################################

TARGET_NAME=bf_serial
TARGET_TYPE=lib
TARGET_COMPILER=both

SOURCES=serial_port_x86.cpp bf_portio.asm portio_x64.cpp
LINUX_SOURCES=portio_linux.cpp 

INCLUDES=
LIBS=

INCLUDE_PATHS=../include/ ../../../include/ ../../../include/std 

LIB_PATHS=

VMM_SOURCES=portio_x64.cpp
VMM_INCLUDE_PATHS=../../../include/std/

################################################################################
# Common
################################################################################

include ../../../../common/common_target.mk
