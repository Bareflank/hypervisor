#
# Bareflank Hypervisor
# Copyright (C) 2015 Assured Information Security, Inc.
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

# ------------------------------------------------------------------------------
# README
# ------------------------------------------------------------------------------

# *** WARNING ***
#
# Configuration variables can only be set prior to running "make". Once the
# build has started, a clean build must be used after any configuration
# variable has been set. Use "make clean-all".

# ------------------------------------------------------------------------------
# Config
# ------------------------------------------------------------------------------

# Build Type
#
# Defines the type of hypervisor that is build. Possible values are Release
# and Debug. Release mode turns on all optimizations and is the default
#set(CMAKE_BUILD_TYPE Release)
#set(CMAKE_BUILD_TYPE Debug)

# Shared vs Static Builds
#
# By default shared libraries are built, and shared libraries must be enabled
# if unit testing is enabled. The library type only applies to the VMM. When
# building using static libraries, the main executables are linked against all
# of the VMM libraries resulting in a single binary that's as small as it's
# going to get. This is the ideal build type but requires open sourcing your
# object files due to the LGPL restriction. If this is not acceptable, please
# contact AIS, Inc at quinnr@ainfosec.com. Finally, both binary types can be
# built simultaniously.
#
#set(BUILD_SHARED_LIBS ON)
#set(BUILD_STATIC_LIBS ON)

# Verbosity
#
# To enable a more verbose build system for debugging build issues, you can
# on the following.
#
# set(CMAKE_VERBOSE_MAKEFILE ON)

# External Directories
#
# THe build system maintains three different directories that may be relocated
# outside of the build folder. The most common directory to relocate is the
# cache directory. If you create these folders up one directory from
# CMAKE_SOURCE_DIR, the build system will automatically use these directories.
# Additionally, you can specify them manually here.
#
#set(CACHE_DIR <path>)
#set(DEPENDS_DIR <path>)
#set(PREFIXES_DIR <path>)

# Enable Bits
#
# There are several enable bits that can be used to enable additional
# functionality, or reduce which portions of the hypervisor are built.
#
#set(ENABLE_BUILD_VMM ON)
#set(ENABLE_BUILD_USERSPACE ON)
#set(ENABLE_BUILD_TEST ON)
#set(ENABLE_COMPILER_WARNINGS ON)
#set(ENABLE_ASAN ON)
#set(ENABLE_USAN ON)
#set(ENABLE_CODECOV ON)
#set(ENABLE_TIDY ON)
#set(ENABLE_FORMAT ON)

# Hypervisor Only (Default)
#
# The following will only build the hypervisor and related tools
#
#set(ENABLE_BUILD_VMM ON)
#set(ENABLE_BUILD_USERSPACE ON)
#set(ENABLE_BUILD_TEST OFF)

# Unit Test Only
#
# The following will only build the unit tests
#
#set(ENABLE_BUILD_VMM OFF)
#set(ENABLE_BUILD_USERSPACE OFF)
#set(ENABLE_BUILD_TEST ON)
