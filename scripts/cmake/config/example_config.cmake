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
# hypervisor and build folder and rename it to "config.cmake".
# For example:
#
# - working
#   - build
#   - hypervisor
#   - boxy # optional
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
set(ENABLE_EXAMPLE_CPUIDCOUNT OFF)
set(ENABLE_EXAMPLE_HOOK OFF)
set(ENABLE_EXAMPLE_RDTSC OFF)
set(ENABLE_EXAMPLE_VPID OFF)

# Override VMM
#
# Setting the OVERRIDE_VMM variable is the same as setting the DEFAULT_VMM
# from the command line. Use this to change which VMM the build system will
# load when you run 'make load` or `make quick`.
#
# set(OVERRIDE_VMM <name>)

# Override VMM Target
#
# This is only needed if you also turn on EFI. If you are building EFI from
# your own extension, you will need to tell the build system what the target
# name is for your VMM so that it will know what target the EFI portion of
# the build system depends on. This simply ensures that the build system
# first compiles your custom VMM before compiling the bareflank.efi. In other
# words, within the build system, this will add a call to add_dependency()
# with the value you provide.
#
# set(OVERRIDE_VMM_TARGET <name>)







# ==============================================================================
# DO NOT MODIFY BELOW
# ==============================================================================

if(ENABLE_DEVELOPER_MODE)
    set(CMAKE_BUILD_TYPE Debug)
else()
    set(CMAKE_BUILD_TYPE Release)
endif()

file(MAKE_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/cache)

# Cache
#
# THe build system maintains it's own cache of all external dependencies to
# eliminate the need to download these dependencies multiple times. The default
# location is in the build folder, but if you plan to do more than one build,
# moving this cache outside of the build folder will speed up build times, and
# prevent needless downloading.
#
set(CACHE_DIR ${CMAKE_CURRENT_LIST_DIR}/cache)

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

set(ENABLE_COMPILER_WARNINGS ON)

# ------------------------------------------------------------------------------
# Boxy
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

if(ENABLE_EXAMPLE_CPUIDCOUNT)
    set_bfm_vmm(example_cpuidcount_vmm)
endif()

if(ENABLE_EXAMPLE_HOOK)
    set_bfm_vmm(example_hook_vmm)
endif()

if(ENABLE_EXAMPLE_RDTSC)
    set_bfm_vmm(example_rdtsc_vmm)
endif()

if(ENABLE_EXAMPLE_VPID)
    set_bfm_vmm(example_vpid_vmm)
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
