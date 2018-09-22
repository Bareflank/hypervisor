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

cmake_minimum_required(VERSION 3.6)
project(hypervisor)

# ------------------------------------------------------------------------------
# Config
# ------------------------------------------------------------------------------

include(${CMAKE_CURRENT_LIST_DIR}/scripts/cmake/config/default.cmake)
include_external_config()

# ------------------------------------------------------------------------------
# Project File
# ------------------------------------------------------------------------------

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

include(scripts/cmake/targets.cmake)

# ------------------------------------------------------------------------------
# General Dependencies
# ------------------------------------------------------------------------------

include_dependency(SOURCE_DEPENDS_DIR gsl)
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
    add_subproject(
        bfdriver none
        NOBUILD
    )

    add_subproject(
        bfelf_loader none
        NOBUILD
    )

    add_subproject(
        bfsdk none
        NOBUILD
    )
endif()

# ------------------------------------------------------------------------------
# VMM Components
# ------------------------------------------------------------------------------

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

if(ENABLE_BUILD_VMM)
    add_subproject(
        bfintrinsics vmm
        DEPENDS bfunwind
    )

    add_subproject(
        bfvmm vmm
        DEPENDS bfunwind
    )

    add_subproject(
        bfvmm_main vmm
        DEPENDS bfvmm
        DEPENDS bfintrinsics
        SOURCE_DIR ${SOURCE_BFVMM_DIR}/src/main
    )
endif()

# ------------------------------------------------------------------------------
# Unit Tests
# ------------------------------------------------------------------------------

if(ENABLE_BUILD_TEST)
    add_subproject(
        bfsdk test
        DEPENDS gsl
        DEPENDS json
        DEPENDS catch
        DEPENDS hippomocks
    )
endif()

if(ENABLE_BUILD_TEST AND NOT WIN32)
    add_subproject(
        bfdummy vmm
        DEPENDS bfunwind
    )

    add_subproject(
        bfdummy_main vmm
        SOURCE_DIR ${SOURCE_BFDUMMY_DIR}/src/main
        DEPENDS bfdummy
    )

    add_subproject(
        bfelf_loader test
        DEPENDS bfsdk
        NOINSTALL
    )

    add_subproject(
        bfdriver test
        DEPENDS bfsdk
        NOINSTALL
    )
endif()

if(ENABLE_BUILD_TEST)
    add_subproject(
        bfm test
        DEPENDS bfsdk
        NOINSTALL
    )

    add_subproject(
        bfruntime test
        DEPENDS bfsdk
        NOINSTALL
    )

    add_subproject(
        bfvmm test
        DEPENDS bfsdk
    )
endif()

# ------------------------------------------------------------------------------
# Userspace Components
# ------------------------------------------------------------------------------

if(ENABLE_BUILD_USERSPACE)
    add_subproject(
        bfintrinsics userspace
        DEPENDS gsl
        DEPENDS json
    )

    add_subproject(
        bfm userspace
        DEPENDS gsl
        DEPENDS json
    )
endif()

# ------------------------------------------------------------------------------
# External Components
# ------------------------------------------------------------------------------

include_external_extensions()

# ------------------------------------------------------------------------------
# EFI Components
# ------------------------------------------------------------------------------

if(ENABLE_BUILD_EFI AND NOT WIN32)
    include_dependency(SOURCE_DEPENDS_DIR gnuefi)

    add_subproject(
        efi efi
        DEPENDS gnuefi ${BFM_VMM_TARGET}
        SOURCE_DIR ${SOURCE_BFDRIVER_DIR}/src/platform/efi
    )
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
