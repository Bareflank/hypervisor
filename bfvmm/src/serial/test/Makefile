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
LD=g++
ASM=nasm

CCFLAGS=
CXXFLAGS=
LDFLAGS=
ASMFLAGS=

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

TARGET_NAME=serial_test
TARGET_TYPE=bin
TARGET_COMPILER=native

OBJDIR=.build
OUTDIR=../bin

SOURCES=serial_test.cpp

INCLUDES=
LIB_PATHS=../bin/native
LIBS=bf_serial

INCLUDE_PATHS=../include/ ../../../include/ ../../../include/std 

################################################################################
# Common
################################################################################

include ../../../../common/common_target.mk
