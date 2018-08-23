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

# To use this config, put this file in the same folder that contains the
# hypervisor and build folder, (and extended apis if your using them), and
# rename it to "config.cmake". For example:
#
# - working
#   - build
#   - hypervisor
#   - extended_apis                     # optional
#   - hypervisor_example_vpid           # optional
#   - hypervisor_example_rdtsc          # optional
#   - hypervisor_example_cpuidcount     # optional
#   - hypervisor_example_msr_bitmap     # optional
#   - config.cmake
#
# Change the options as needed, and then from the build folder, run the
# following:
#
# > cmake ../hypervisor
# > make -j<# of cpus>
#

# *** WARNING ***
#
# Configuration variables can only be set prior to running "make". Once the
# build has started, a new build folder is needed before any configuration
# changes can be made.

# ------------------------------------------------------------------------------
# Options
# ------------------------------------------------------------------------------

# Developer Mode
#
# Turns on build options useful for developers. If you plan to submit a PR to
# any of the Bareflank repos, this option will be needed as it enables
# formatting, static / dynamic analysis, etc...
#
set(ENABLE_DEVELOPER_MODE OFF)

# Tests only
#
# If you are only interested in compiling the tests, this option can speed up
# your build times .
#
set(ENABLE_TESTS_ONLY OFF)

# Extended APIs
#
# This option enables the use of the extended APIs. It assumes the extended
# APIs are located in the same directory as this configuration file.
#
set(ENABLE_EXTENDED_APIS OFF)

# Enable EFI
#
# This will enable building EFI targets after the VMM has compiled. Note that
# this forces static build, disables testing, ASAN, codecov and clang tidy,
# and requries the VMM be compiled
#
set(ENABLE_BUILD_EFI OFF)

# Examples
#
# These options enable the examples
#
set(ENABLE_HYPERVISOR_EXAMPLE_VPID OFF)
set(ENABLE_HYPERVISOR_EXAMPLE_RDTSC OFF)
set(ENABLE_HYPERVISOR_EXAMPLE_CPUIDCOUNT OFF)
set(ENABLE_HYPERVISOR_EXAMPLE_MSR_BITMAP OFF)
set(ENABLE_EXTENDED_APIS_EXAMPLE_HOOK OFF)

# Override VMM
#
# If the override VMM is set, this VMM will be used instead of the default VMM
# based on the current configuration. Note that you can also set the override
# VMM target to use, which might be needed for EFI so that EFI knows which
# target to wait for
#
# set(OVERRIDE_VMM <name>)
# set(OVERRIDE_VMM_TARGET <name>)

# Override Compiler Warnings
#
# Tells the configuration that you want -Werror enabled regardless of the
# setting of developer mode
#
# set(OVERRIDE_COMPILER_WARNINGS ON)

# ------------------------------------------------------------------------------
# Config Variables (No Need To Modify)
# ------------------------------------------------------------------------------

# Build Type
#
# Defines the type of hypervisor that is built. Possible values are Release
# and Debug. Release mode turns on all optimizations and is the default
#
if(ENABLE_DEVELOPER_MODE)
    set(CMAKE_BUILD_TYPE Debug)
else()
    set(CMAKE_BUILD_TYPE Release)
endif()

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
if(ENABLE_DEVELOPER_MODE AND NOT ENABLE_BUILD_EFI)
    set(BUILD_SHARED_LIBS ON)
    set(BUILD_STATIC_LIBS OFF)
else()
    set(BUILD_SHARED_LIBS OFF)
    set(BUILD_STATIC_LIBS ON)
endif()

# Cache
#
# THe build system maintains it's own cache of all external dependencies to
# eliminate the need to download these dependencies multiple times. The default
# location is in the build folder, but if you plan to do more than one build,
# moving this cache outside of the build folder will speed up build times, and
# prevent needless downloading.
#
set(CACHE_DIR ${CMAKE_CURRENT_LIST_DIR}/cache)

# Enable Bits
#
# There are several enable bits that can be used to enable additional
# functionality, or reduce which portions of the hypervisor are built.
#
if(ENABLE_TESTS_ONLY)
    set(ENABLE_BUILD_VMM OFF)
    set(ENABLE_BUILD_USERSPACE OFF)
else()
    set(ENABLE_BUILD_VMM ON)
    set(ENABLE_BUILD_USERSPACE ON)
endif()

if(ENABLE_DEVELOPER_MODE AND NOT ENABLE_BUILD_EFI)
    set(ENABLE_BUILD_TEST ON)
else()
    set(ENABLE_BUILD_TEST OFF)
endif()

if(ENABLE_DEVELOPER_MODE AND NOT ENABLE_BUILD_EFI AND NOT WIN32)
    set(ENABLE_ASAN ON)
    set(ENABLE_TIDY ON)
    set(ENABLE_FORMAT ON)
    set(ENABLE_CODECOV ON)
else()
    set(ENABLE_ASAN OFF)
    set(ENABLE_TIDY OFF)
    set(ENABLE_FORMAT ON)
    set(ENABLE_CODECOV OFF)
endif()

# Compiler Warnings
#
# Enables compiler warnings. This option should always be on when developing.
# Not that Release builds add "-Werror".
#
if(ENABLE_DEVELOPER_MODE AND NOT OVERRIDE_COMPILER_WARNINGS)
    set(ENABLE_COMPILER_WARNINGS OFF)
else()
    set(ENABLE_COMPILER_WARNINGS ON)
endif()

# ------------------------------------------------------------------------------
# Extended APIs
# ------------------------------------------------------------------------------

if(ENABLE_EXTENDED_APIS)
    set_bfm_vmm(eapis_bfvmm)
    list(APPEND EXTENSION
        ${CMAKE_CURRENT_LIST_DIR}/extended_apis
    )
endif()

# ------------------------------------------------------------------------------
# Examples
# ------------------------------------------------------------------------------

if(ENABLE_HYPERVISOR_EXAMPLE_VPID)
    set_bfm_vmm(example_vmm)
    list(APPEND EXTENSION
        ${CMAKE_CURRENT_LIST_DIR}/hypervisor_example_vpid
    )
endif()

if(ENABLE_HYPERVISOR_EXAMPLE_RDTSC)
    set_bfm_vmm(example_vmm)
    list(APPEND EXTENSION
        ${CMAKE_CURRENT_LIST_DIR}/hypervisor_example_rdtsc
    )
endif()

if(ENABLE_HYPERVISOR_EXAMPLE_CPUIDCOUNT)
    set_bfm_vmm(example_vmm)
    list(APPEND EXTENSION
        ${CMAKE_CURRENT_LIST_DIR}/hypervisor_example_cpuidcount
    )
endif()

if(ENABLE_HYPERVISOR_EXAMPLE_MSR_BITMAP)
    set_bfm_vmm(example_vmm)
    list(APPEND EXTENSION
        ${CMAKE_CURRENT_LIST_DIR}/hypervisor_example_msr_bitmap
    )
endif()

if(ENABLE_EXTENDED_APIS_EXAMPLE_HOOK)
    set_bfm_vmm(example_vmm)
    list(APPEND EXTENSION
        ${CMAKE_CURRENT_LIST_DIR}/extended_apis_example_hook
    )
endif()

# ------------------------------------------------------------------------------
# Override VMM
# ------------------------------------------------------------------------------

if(OVERRIDE_VMM)
    if(OVERRIDE_VMM_TARGET)
        set_bfm_vmm(${OVERRIDE_VMM} TARGET ${OVERRIDE_VMM_TARGET})
    else()
        set_bfm_vmm(${OVERRIDE_VMM})
    endif()
endif()
