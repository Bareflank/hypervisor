#
# Copyright (C) 2019 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

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

# Boxy
#
# This option enables the use of the boxy. It assumes that
# boxy is located in the same directory as this configuration file.
#
set(ENABLE_BOXY OFF)

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
# based on the current configuration.
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
if(ENABLE_DEVELOPER_MODE AND NOT ENABLE_BUILD_EFI)
    set(ENABLE_BUILD_TEST ON)
else()
    set(ENABLE_BUILD_TEST OFF)
endif()

if(ENABLE_DEVELOPER_MODE AND NOT ENABLE_BUILD_EFI AND NOT WIN32 AND NOT CYGWIN)
    set(ENABLE_ASAN ON)
    set(ENABLE_TIDY ON)
    set(ENABLE_FORMAT ON)
    set(ENABLE_CODECOV ON)
else()
    set(ENABLE_ASAN OFF)
    set(ENABLE_TIDY OFF)
    set(ENABLE_FORMAT OFF)
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
    set(ENABLE_COMPILER_WARNINGS ${OVERRIDE_COMPILER_WARNINGS})
endif()

# ------------------------------------------------------------------------------
# Hyperkernel
# ------------------------------------------------------------------------------

if(ENABLE_BOXY)
    set_bfm_vmm(boxy_bfvmm)
    list(APPEND EXTENSION
        ${CMAKE_CURRENT_LIST_DIR}/boxy
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
