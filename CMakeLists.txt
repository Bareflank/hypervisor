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

cmake_minimum_required(VERSION 3.13)
project(hypervisor)

# ------------------------------------------------------------------------------
# Modules
# ------------------------------------------------------------------------------

include(ProcessorCount)
include(ExternalProject)

# ------------------------------------------------------------------------------
# Configs
# ------------------------------------------------------------------------------

include(${CMAKE_CURRENT_LIST_DIR}/scripts/cmake/config/default.cmake)
include_external_config()

# ------------------------------------------------------------------------------
# Macros
# ------------------------------------------------------------------------------

include(${SOURCE_CMAKE_DIR}/macros.cmake)

# ------------------------------------------------------------------------------
# Testing
# ------------------------------------------------------------------------------

if(ENABLE_BUILD_TEST)
    include(CTest)
    enable_testing(true)
endif()

# ------------------------------------------------------------------------------
# Sub-project includes
# ------------------------------------------------------------------------------

add_project_include(${SOURCE_CMAKE_DIR}/macros.cmake)

# ------------------------------------------------------------------------------
# BFM VMM
# ------------------------------------------------------------------------------

set_bfm_vmm(${DEFAULT_VMM} DEFAULT TARGET bfvmm)
message(STATUS "Bareflank Manager VMM")
message(STATUS "    vmm: ${BFM_VMM}")
message(STATUS "    target: ${BFM_VMM_TARGET}")

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

include(${SOURCE_CMAKE_DIR}/targets.cmake)

# ------------------------------------------------------------------------------
# General Dependencies
# ------------------------------------------------------------------------------

include_dependency(SOURCE_DEPENDS_DIR gsl)
include_dependency(SOURCE_DEPENDS_DIR cxxopts)
include_dependency(SOURCE_DEPENDS_DIR json)
include_dependency(SOURCE_DEPENDS_DIR astyle)
include_dependency(SOURCE_DEPENDS_DIR clang_tidy)
include_dependency(SOURCE_DEPENDS_DIR catch)
include_dependency(SOURCE_DEPENDS_DIR hippomocks)

# ------------------------------------------------------------------------------
# Package File
# ------------------------------------------------------------------------------

execute_process(COMMAND ${CMAKE_COMMAND} -E make_directory ${EXPORT_DIR})
file(APPEND ${PKG_FILE} "")

# ------------------------------------------------------------------------------
# Root Targets
# ------------------------------------------------------------------------------

add_subproject(bfroot vmm SOURCE_DIR ${SOURCE_CMAKE_DIR})
add_subproject(bfroot efi SOURCE_DIR ${SOURCE_CMAKE_DIR})
add_subproject(bfroot test SOURCE_DIR ${SOURCE_CMAKE_DIR} DEPENDS catch)
add_subproject(bfroot userspace SOURCE_DIR ${SOURCE_CMAKE_DIR})

# ------------------------------------------------------------------------------
# VMM Components
# ------------------------------------------------------------------------------

include_dependency(SOURCE_DEPENDS_DIR binutils)
include_dependency(SOURCE_DEPENDS_DIR newlib)
include_dependency(SOURCE_DEPENDS_DIR llvm)
include_dependency(SOURCE_DEPENDS_DIR libcxxabi)
include_dependency(SOURCE_DEPENDS_DIR libcxx)

add_subproject(bfsdk vmm DEPENDS bfroot)

if(ENABLE_BUILD_VMM OR (ENABLE_BUILD_TEST AND NOT WIN32))
    add_subproject(bfruntime vmm DEPENDS gsl libcxx bfroot)
    add_subproject(bfunwind vmm DEPENDS bfruntime)
endif()

if(ENABLE_BUILD_VMM)
    add_subproject(bfintrinsics vmm DEPENDS bfruntime)
    add_subproject(bfvmm vmm DEPENDS bfunwind bfintrinsics bfsdk)
endif()

# ------------------------------------------------------------------------------
# Unit Tests
# ------------------------------------------------------------------------------

if(ENABLE_BUILD_TEST)
    add_subproject(bfsdk test DEPENDS gsl json hippomocks bfroot)
endif()

if(ENABLE_BUILD_TEST AND NOT WIN32)
    add_subproject(bfdummy vmm DEPENDS bfunwind)
    add_subproject(bfdriver test DEPENDS bfsdk)
endif()

if(ENABLE_BUILD_TEST)
    add_subproject(bfm test DEPENDS bfsdk)
    add_subproject(bfruntime test DEPENDS bfsdk)
    add_subproject(bfvmm test DEPENDS bfsdk)
endif()

# ------------------------------------------------------------------------------
# Userspace Components
# ------------------------------------------------------------------------------

if(ENABLE_BUILD_USERSPACE)
    add_subproject(bfsdk userspace DEPENDS bfroot)
    add_subproject(bfintrinsics userspace DEPENDS gsl json bfroot)
    add_subproject(bfm userspace DEPENDS gsl json cxxopts bfroot)
    add_subproject(bfack userspace DEPENDS bfintrinsics)
endif()

# ------------------------------------------------------------------------------
# External Components
# ------------------------------------------------------------------------------

list(APPEND EXTENSION ${SOURCE_EXAMPLES_DIR}/cpuidcount)
list(APPEND EXTENSION ${SOURCE_EXAMPLES_DIR}/hook)
list(APPEND EXTENSION ${SOURCE_EXAMPLES_DIR}/rdtsc)
list(APPEND EXTENSION ${SOURCE_EXAMPLES_DIR}/vpid)

include_external_extensions()

# ------------------------------------------------------------------------------
# EFI Components
# ------------------------------------------------------------------------------

if(ENABLE_BUILD_EFI AND NOT WIN32)
    include_dependency(SOURCE_DEPENDS_DIR gnuefi)
    add_subproject(bfdriver efi DEPENDS bfroot gnuefi ${BFM_VMM_TARGET})
endif()

# ------------------------------------------------------------------------------
# Force Rebuild
# ------------------------------------------------------------------------------

get_property(FORCE_REBUILD GLOBAL PROPERTY "FORCE_REBUILD")

if(FORCE_REBUILD STREQUAL "ON")
    set_property(GLOBAL PROPERTY "FORCE_REBUILD" "OFF")
    file(REMOVE_RECURSE ${DEPENDS_DIR})
    file(REMOVE_RECURSE ${PREFIXES_DIR})
    message(FATAL_ERROR "${Yellow}dependencies updated, rebuild is required. Rerun cmake${ColorReset}")
endif()


# TODO:
#
# Detect if the flags have changed, delete the depends and prefixes, and then
# tell the user that cmake needs to be run again as a rebuild is required.

# ------------------------------------------------------------------------------
# Validate Build
# ------------------------------------------------------------------------------

include(scripts/cmake/validate.cmake)
validate_build()

# ------------------------------------------------------------------------------
# Banners
# ------------------------------------------------------------------------------

print_banner()
print_usage()

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

git_dir_script()

# ------------------------------------------------------------------------------
# Info
# ------------------------------------------------------------------------------

if(NOT WIN32)
    add_custom_command(TARGET info COMMAND ${CMAKE_COMMAND} -E cmake_echo_color " ")
endif()
