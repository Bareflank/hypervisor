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

cmake_minimum_required(VERSION 3.10)
project(hypervisor)

# ------------------------------------------------------------------------------
# Modules
# ------------------------------------------------------------------------------

include(ProcessorCount)
include(ExternalProject)

# ------------------------------------------------------------------------------
# Config
# ------------------------------------------------------------------------------

include(${CMAKE_CURRENT_LIST_DIR}/scripts/cmake/config/default.cmake)
include_external_config()

# ------------------------------------------------------------------------------
# Testing
# ------------------------------------------------------------------------------

if(BUILD_TEST)
    include(CTest)
    enable_testing(true)
endif()

# ------------------------------------------------------------------------------
# Super-build include files
# ------------------------------------------------------------------------------

include(${SOURCE_CMAKE_DIR}/genexp.cmake)
include(${SOURCE_CMAKE_DIR}/macros.cmake)
include(${SOURCE_CMAKE_DIR}/targets.cmake)

# ------------------------------------------------------------------------------
# Subproject include files
# ------------------------------------------------------------------------------

add_project_include(${SOURCE_CMAKE_DIR}/genexp.cmake)
add_project_include(${SOURCE_CMAKE_DIR}/macros.cmake)

# ------------------------------------------------------------------------------
# BFM VMM
# ------------------------------------------------------------------------------

set_bfm_vmm(${DEFAULT_VMM} DEFAULT)
message(STATUS "Bareflank Manager VMM")
message(STATUS "    vmm: ${BFM_VMM}")
message(STATUS "    target: ${BFM_VMM_TARGET}")

# ------------------------------------------------------------------------------
# External Dependencies
# ------------------------------------------------------------------------------

include_dependency(SOURCE_DEPENDS_DIR gsl)
include_dependency(SOURCE_DEPENDS_DIR cxxopts)
include_dependency(SOURCE_DEPENDS_DIR json)
include_dependency(SOURCE_DEPENDS_DIR astyle)
include_dependency(SOURCE_DEPENDS_DIR clang_tidy)
include_dependency(SOURCE_DEPENDS_DIR catch)
include_dependency(SOURCE_DEPENDS_DIR hippomocks)
include_dependency(SOURCE_DEPENDS_DIR python)
include_dependency(SOURCE_DEPENDS_DIR binutils)

# ------------------------------------------------------------------------------
# No Build Components
# ------------------------------------------------------------------------------

if(BUILD_VMM)
    add_targets(bfdriver none ${SOURCE_BFDRIVER_DIR}/src)
endif()

# ------------------------------------------------------------------------------
# Root Targets
# ------------------------------------------------------------------------------

add_subproject(bfroot vmm SOURCE_DIR ${CMAKE_SOURCE_DIR}/bfroot)
add_subproject(bfroot test SOURCE_DIR ${CMAKE_SOURCE_DIR}/bfroot)
add_subproject(bfroot userspace SOURCE_DIR ${CMAKE_SOURCE_DIR}/bfroot)

# ------------------------------------------------------------------------------
# VMM Components
# ------------------------------------------------------------------------------

add_subproject(bfutil vmm DEPENDS bfroot SOURCE_DIR ${SOURCE_BFUTIL_DIR})

#if(NOT WIN32)
#    if(NOT BUILD_BINUTILS)
#        add_subproject(
#            bfdso vmm
#            SOURCE_DIR ${SOURCE_BFRUNTIME_DIR}/src/dso
#        )
#    else()
#        add_subproject(
#            bfdso vmm
#            SOURCE_DIR ${SOURCE_BFRUNTIME_DIR}/src/dso
#            DEPENDS binutils
#        )
#    endif()
#endif()
#
#include_dependency(SOURCE_DEPENDS_DIR newlib)
#include_dependency(SOURCE_DEPENDS_DIR llvm)
#include_dependency(SOURCE_DEPENDS_DIR libcxxabi)
#include_dependency(SOURCE_DEPENDS_DIR libcxx)
#
#if(BUILD_VMM OR (BUILD_TEST AND NOT WIN32))
#    add_subproject(
#        bfcrt vmm
#        DEPENDS gsl
#        DEPENDS libcxx
#        DEPENDS bfutil
#        SOURCE_DIR ${SOURCE_BFRUNTIME_DIR}/src/crt
#    )
#
#    add_subproject(
#        bfpthread vmm
#        DEPENDS gsl
#        DEPENDS libcxx
#        DEPENDS bfcrt
#        SOURCE_DIR ${SOURCE_BFRUNTIME_DIR}/src/pthread
#    )
#
#    add_subproject(
#        bfsyscall vmm
#        DEPENDS gsl
#        DEPENDS libcxx
#        DEPENDS bfpthread
#        SOURCE_DIR ${SOURCE_BFRUNTIME_DIR}/src/syscall
#    )
#
#    add_subproject(
#        bfunwind vmm
#        DEPENDS bfcrt
#        DEPENDS bfpthread
#        DEPENDS bfsyscall
#    )
#endif()
#
#if(BUILD_VMM)
#    add_subproject(bfintrinsics vmm DEPENDS bfunwind)
#    add_subproject(bfvmm vmm DEPENDS bfintrinsics)
#endif()
#
## ------------------------------------------------------------------------------
## Unit Tests
## ------------------------------------------------------------------------------
#
##if(BUILD_TEST)
##    add_subproject(
##        bfutil test
##        DEPENDS gsl
##        DEPENDS json
##        DEPENDS catch
##        DEPENDS hippomocks
##    )
##endif()
##
##if(BUILD_TEST AND NOT WIN32)
##    add_subproject(
##        bfdummy vmm
##        DEPENDS bfunwind
##    )
##
##    add_subproject(
##        bfdummy_main vmm
##        SOURCE_DIR ${SOURCE_BFDUMMY_DIR}/src/main
##        DEPENDS bfdummy
##    )
##
##    add_subproject(
##        bfdriver test
##        DEPENDS bfutil
##        NOINSTALL
##    )
##endif()
##
##if(BUILD_TEST)
##    add_subproject(
##        bfm test
##        DEPENDS bfutil
##        NOINSTALL
##    )
##
##    add_subproject(
##        bfruntime test
##        DEPENDS bfutil
##        NOINSTALL
##    )
##
##    add_subproject(
##        bfvmm test
##        DEPENDS bfutil
##    )
##endif()
##
### ------------------------------------------------------------------------------
### Userspace Components
### ------------------------------------------------------------------------------
##
#if(BUILD_USERSPACE)
#    #    add_subproject(
#    #        bfintrinsics userspace
#    #        DEPENDS gsl
#    #        DEPENDS json
#    #    )
#
##    add_subproject(
##        bfm userspace
##        DEPENDS gsl
##        DEPENDS json
##        DEPENDS cxxopts
##    )
#endif()
##
### ------------------------------------------------------------------------------
### External Components
### ------------------------------------------------------------------------------
##
##include_external_extensions()
##
### ------------------------------------------------------------------------------
### EFI Components
### ------------------------------------------------------------------------------
##
##if(BUILD_EFI AND NOT WIN32)
##    include_dependency(SOURCE_DEPENDS_DIR gnuefi)
##
##    add_subproject(
##        efi efi
##        DEPENDS gnuefi ${BFM_VMM_TARGET}
##        SOURCE_DIR ${SOURCE_BFDRIVER_DIR}/src/platform/efi
##    )
##endif()
##
### ------------------------------------------------------------------------------
### Force Rebuild
### ------------------------------------------------------------------------------
##
##get_property(FORCE_REBUILD GLOBAL PROPERTY "FORCE_REBUILD")
##
##if(FORCE_REBUILD STREQUAL "ON")
##    set_property(GLOBAL PROPERTY "FORCE_REBUILD" "OFF")
##    file(REMOVE_RECURSE ${DEPENDS_DIR})
##    file(REMOVE_RECURSE ${PREFIXES_DIR})
##    message(FATAL_ERROR "${Yellow}dependencies updated, rebuild is required. Rerun cmake${ColorReset}")
##endif()
##
### TODO:
###
### Detect if the flags have changed, delete the depends and prefixes, and then
### tell the user that cmake needs to be run again as a rebuild is required.
##
### ------------------------------------------------------------------------------
### Validate Build
### ------------------------------------------------------------------------------
##
##include(scripts/cmake/validate.cmake)
##validate_build()
##
### ------------------------------------------------------------------------------
### Banners
### ------------------------------------------------------------------------------
##
##print_banner()
##print_usage()
##
### ------------------------------------------------------------------------------
### Helpers
### ------------------------------------------------------------------------------
##
##git_dir_script()
##
### ------------------------------------------------------------------------------
### Info
### ------------------------------------------------------------------------------
##
##if(NOT WIN32)
##    add_custom_command(TARGET info COMMAND ${CMAKE_COMMAND} -E cmake_echo_color " ")
##endif()
