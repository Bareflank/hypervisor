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

if(ENABLE_BUILD_TEST)
    include(CTest)
    enable_testing(true)
endif()

# ------------------------------------------------------------------------------
# Root Targets
# ------------------------------------------------------------------------------

ExternalProject_Add(
    bfroot
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfroot
    CMAKE_ARGS -DBUILD_TARGET_ARCH=${BUILD_TARGET_ARCH}
               -DOSTYPE=${OSTYPE}
               -DVMM_PREFIX_PATH=${VMM_PREFIX_PATH}
               -DENABLE_BUILD_EFI=${ENABLE_BUILD_EFI}
               -DEXPORT_DIR=${EXPORT_DIR}
               -DABITYPE=${ABITYPE}
               -DENABLE_ASAN=${ENABLE_ASAN}
               -DENABLE_USAN=${ENABLE_USAN}
               -DENABLE_CODECOV=${ENABLE_CODECOV}
               -DENABLE_BUILD_VMM=${ENABLE_BUILD_VMM}
               -DENABLE_BUILD_TEST=${ENABLE_BUILD_TEST}
               -DENABLE_BUILD_USERSPACE=${ENABLE_BUILD_USERSPACE}
)
set(PROJECT_INCLUDE_LIST "${PROJECT_INCLUDE_LIST}|${EXPORT_DIR}/bfroot.cmake")

# ------------------------------------------------------------------------------
# Macros
# ------------------------------------------------------------------------------

include(${SOURCE_CMAKE_DIR}/macros.cmake)
add_project_include(${SOURCE_CMAKE_DIR}/macros.cmake)

# ------------------------------------------------------------------------------
# BFM VMM
# ------------------------------------------------------------------------------

set_bfm_vmm(${DEFAULT_VMM} DEFAULT)
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
include_dependency(SOURCE_DEPENDS_DIR python)

# ------------------------------------------------------------------------------
# No Build Components
# ------------------------------------------------------------------------------

if(ENABLE_BUILD_VMM)
    #    add_subproject(bfdriver none NOBUILD)
endif()

# ------------------------------------------------------------------------------
# VMM Components
# ------------------------------------------------------------------------------

add_subproject(bfutil vmm SOURCE_DIR ${SOURCE_BFUTIL_DIR})
include_dependency(SOURCE_DEPENDS_DIR binutils)
if(NOT WIN32)
    if(NOT ENABLE_BUILD_BINUTILS)
        add_subproject(
            bfdso vmm
            SOURCE_DIR ${SOURCE_BFRUNTIME_DIR}/src/dso
        )
    else()
        add_subproject(
            bfdso vmm
            SOURCE_DIR ${SOURCE_BFRUNTIME_DIR}/src/dso
            DEPENDS binutils
        )
    endif()
endif()

include_dependency(SOURCE_DEPENDS_DIR newlib)
include_dependency(SOURCE_DEPENDS_DIR llvm)
include_dependency(SOURCE_DEPENDS_DIR libcxxabi)
include_dependency(SOURCE_DEPENDS_DIR libcxx)

if(ENABLE_BUILD_VMM OR (ENABLE_BUILD_TEST AND NOT WIN32))
    add_subproject(
        bfcrt vmm
        DEPENDS gsl
        DEPENDS libcxx
        SOURCE_DIR ${SOURCE_BFRUNTIME_DIR}/src/crt
    )

    add_subproject(
        bfpthread vmm
        DEPENDS gsl
        DEPENDS libcxx
        SOURCE_DIR ${SOURCE_BFRUNTIME_DIR}/src/pthread
    )

    add_subproject(
        bfsyscall vmm
        DEPENDS gsl
        DEPENDS libcxx
        SOURCE_DIR ${SOURCE_BFRUNTIME_DIR}/src/syscall
    )

    add_subproject(
        bfunwind vmm
        DEPENDS bfcrt
        DEPENDS bfpthread
        DEPENDS bfsyscall
    )
endif()

#if(ENABLE_BUILD_VMM)
#    add_subproject(
#        bfintrinsics vmm
#        DEPENDS bfunwind
#    )
#
#    add_subproject(
#        bfvmm vmm
#        DEPENDS bfunwind
#    )
#
#    add_subproject(
#        bfvmm_main vmm
#        DEPENDS bfvmm
#        DEPENDS bfintrinsics
#        SOURCE_DIR ${SOURCE_BFVMM_DIR}/src/main
#    )
#endif()

# ------------------------------------------------------------------------------
# Unit Tests
# ------------------------------------------------------------------------------

#if(ENABLE_BUILD_TEST)
#    add_subproject(
#        bfutil test
#        DEPENDS gsl
#        DEPENDS json
#        DEPENDS catch
#        DEPENDS hippomocks
#    )
#endif()
#
#if(ENABLE_BUILD_TEST AND NOT WIN32)
#    add_subproject(
#        bfdummy vmm
#        DEPENDS bfunwind
#    )
#
#    add_subproject(
#        bfdummy_main vmm
#        SOURCE_DIR ${SOURCE_BFDUMMY_DIR}/src/main
#        DEPENDS bfdummy
#    )
#
#    add_subproject(
#        bfdriver test
#        DEPENDS bfutil
#        NOINSTALL
#    )
#endif()
#
#if(ENABLE_BUILD_TEST)
#    add_subproject(
#        bfm test
#        DEPENDS bfutil
#        NOINSTALL
#    )
#
#    add_subproject(
#        bfruntime test
#        DEPENDS bfutil
#        NOINSTALL
#    )
#
#    add_subproject(
#        bfvmm test
#        DEPENDS bfutil
#    )
#endif()
#
## ------------------------------------------------------------------------------
## Userspace Components
## ------------------------------------------------------------------------------
#
#if(ENABLE_BUILD_USERSPACE)
#    add_subproject(
#        bfintrinsics userspace
#        DEPENDS gsl
#        DEPENDS json
#    )
#
#    add_subproject(
#        bfm userspace
#        DEPENDS gsl
#        DEPENDS json
#        DEPENDS cxxopts
#    )
#endif()
#
## ------------------------------------------------------------------------------
## External Components
## ------------------------------------------------------------------------------
#
#include_external_extensions()
#
## ------------------------------------------------------------------------------
## EFI Components
## ------------------------------------------------------------------------------
#
#if(ENABLE_BUILD_EFI AND NOT WIN32)
#    include_dependency(SOURCE_DEPENDS_DIR gnuefi)
#
#    add_subproject(
#        efi efi
#        DEPENDS gnuefi ${BFM_VMM_TARGET}
#        SOURCE_DIR ${SOURCE_BFDRIVER_DIR}/src/platform/efi
#    )
#endif()
#
## ------------------------------------------------------------------------------
## Force Rebuild
## ------------------------------------------------------------------------------
#
#get_property(FORCE_REBUILD GLOBAL PROPERTY "FORCE_REBUILD")
#
#if(FORCE_REBUILD STREQUAL "ON")
#    set_property(GLOBAL PROPERTY "FORCE_REBUILD" "OFF")
#    file(REMOVE_RECURSE ${DEPENDS_DIR})
#    file(REMOVE_RECURSE ${PREFIXES_DIR})
#    message(FATAL_ERROR "${Yellow}dependencies updated, rebuild is required. Rerun cmake${ColorReset}")
#endif()
#
## TODO:
##
## Detect if the flags have changed, delete the depends and prefixes, and then
## tell the user that cmake needs to be run again as a rebuild is required.
#
## ------------------------------------------------------------------------------
## Validate Build
## ------------------------------------------------------------------------------
#
#include(scripts/cmake/validate.cmake)
#validate_build()
#
## ------------------------------------------------------------------------------
## Banners
## ------------------------------------------------------------------------------
#
#print_banner()
#print_usage()
#
## ------------------------------------------------------------------------------
## Helpers
## ------------------------------------------------------------------------------
#
#git_dir_script()
#
## ------------------------------------------------------------------------------
## Info
## ------------------------------------------------------------------------------
#
#if(NOT WIN32)
#    add_custom_command(TARGET info COMMAND ${CMAKE_COMMAND} -E cmake_echo_color " ")
#endif()
