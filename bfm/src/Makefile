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
# FLAGS
################################################################################

CC=gcc
CXX=g++
LD=g++
RM=rm -rf
MD=mkdir -p

CCFLAGS=
CXXFLAGS=-std=c++14
LDFLAGS=

DEFINES=

################################################################################
# Sources
################################################################################

TARGET_NAME=bfm
TARGET_TYPE=lib

OBJDIR=.build
OUTDIR=../bin

SOURCES+=command_line_parser.cpp
SOURCES+=debug.cpp
SOURCES+=file.cpp
SOURCES+=ioctl_driver.cpp
SOURCES+=split.cpp

LINUX_SOURCES+=ioctl.cpp
LINUX_SOURCES+=ioctl_private.cpp

INCLUDES=
LIBS=

INCLUDE_PATHS=./ ../include/ ../../include/
LIB_PATHS=

LINUX_INCLUDE_PATHS=./arch/linux/

VPATH=arch/linux

################################################################################
# Common
################################################################################

include ../../common/common_target.mk
