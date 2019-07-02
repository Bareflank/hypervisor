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

# Boxy
#
# This option enables the use of the boxy. It assumes that
# boxy is located in the same directory as this configuration file as stated
# in the example working directory above.
#
set(ENABLE_BOXY OFF)

# Enable EFI
#
# This will enable building EFI targets after the VMM has compiled. Note that
# this only works on Linux (or the Linux subsystem for Windows)
#
set(ENABLE_BUILD_EFI OFF)

# Developer Mode
#
# Turns on build options useful for developers. If you plan to submit a PR to
# any of the Bareflank repos, this option will be needed as it enables
# formatting, static / dynamic analysis, etc...
#
set(ENABLE_DEVELOPER_MODE OFF)

# ------------------------------------------------------------------------------
# Override Options
# ------------------------------------------------------------------------------

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

# Override Linux
#
# This is only useful when Boxy is enabled. This allows you to override the
# Linux repo that you are using. By default, if you do not set this variable,
# Boxy will download our version of Linux for you. If you are however a
# developer working on our version of Linux, you will need your own forked
# version of our Linux. This allows you to specify the location of your forked
# version so that Boxy will use your version instead of its default version.
#
# set(LINUX_DIR <path>)

# ==============================================================================
# DO NOT MODIFY BELOW
# ==============================================================================

file(MAKE_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/cache)
set(CACHE_DIR ${CMAKE_CURRENT_LIST_DIR}/cache)

if(ENABLE_DEVELOPER_MODE)
    set(ENABLE_BUILD_TEST ON)
    set(CMAKE_BUILD_TYPE Debug)
    set(ENABLE_COMPILER_WARNINGS OFF)
else()
    set(ENABLE_BUILD_TEST OFF)
    set(CMAKE_BUILD_TYPE Release)
    set(ENABLE_COMPILER_WARNINGS ON)
endif()

if(ENABLE_DEVELOPER_MODE AND NOT WIN32 AND NOT CYGWIN)
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

if(ENABLE_BOXY)
    set_bfm_vmm(boxy_vmm)
    list(APPEND EXTENSION
        ${CMAKE_CURRENT_LIST_DIR}/boxy
    )
endif()

if(OVERRIDE_VMM)
    if(OVERRIDE_VMM_TARGET)
        set_bfm_vmm(${OVERRIDE_VMM} TARGET ${OVERRIDE_VMM_TARGET})
    else()
        set_bfm_vmm(${OVERRIDE_VMM})
    endif()
endif()
