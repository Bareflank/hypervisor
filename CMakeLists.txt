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
# BFM VMM
# ------------------------------------------------------------------------------

set_bfm_vmm(vmm TARGET bfvmm_x86_64-vmm-elf)
message(STATUS "Bareflank Manager VMM")
message(STATUS "    vmm: ${BFM_VMM}")
message(STATUS "    target: ${BFM_VMM_TARGET}")

# ------------------------------------------------------------------------------
# Superbuild include files
# ------------------------------------------------------------------------------

include(${SOURCE_CMAKE_DIR}/macros.cmake)
include(${SOURCE_CMAKE_DIR}/targets.cmake)

# ------------------------------------------------------------------------------
# Subproject include files
# ------------------------------------------------------------------------------

add_project_include(${SOURCE_CMAKE_DIR}/macros.cmake)

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

if(BUILD_VMM)
    add_targets(bfdriver none ${SOURCE_BFDRIVER_DIR}/src)
endif()

# ------------------------------------------------------------------------------
# Package File
# ------------------------------------------------------------------------------

execute_process(COMMAND ${CMAKE_COMMAND} -E make_directory ${EXPORT_DIR})
file(TOUCH ${PKG_FILE})

# ------------------------------------------------------------------------------
# Root Targets
# ------------------------------------------------------------------------------

add_subproject(bfroot vmm)
add_subproject(bfroot test DEPENDS catch)
add_subproject(bfroot userspace)
add_subproject(bfroot efi)

# ------------------------------------------------------------------------------
# VMM Components
# ------------------------------------------------------------------------------

include_dependency(SOURCE_DEPENDS_DIR binutils)

if(NOT WIN32)
    add_subproject(
        bfutil vmm
        DEPENDS bfroot
    )
    if(NOT BUILD_BINUTILS)
        add_subproject(
            bfdso vmm
            DEPENDS bfroot
        )
    else()
        add_subproject(
            bfdso vmm
            DEPENDS binutils
            DEPENDS bfroot
        )
    endif()
endif()

include_dependency(SOURCE_DEPENDS_DIR newlib)
include_dependency(SOURCE_DEPENDS_DIR llvm)
include_dependency(SOURCE_DEPENDS_DIR libcxxabi)
include_dependency(SOURCE_DEPENDS_DIR libcxx)

if(BUILD_VMM OR (BUILD_TEST AND NOT WIN32))
    add_subproject(
        bfruntime vmm
        DEPENDS gsl
        DEPENDS libcxx
        DEPENDS bfroot
    )
endif()

if(BUILD_VMM)
    add_subproject(
        bfintrinsics vmm
        DEPENDS bfroot
    )
    add_subproject(
        bfvmm vmm
        DEPENDS bfintrinsics
        DEPENDS bfruntime
    )
endif()

# ------------------------------------------------------------------------------
# Unit Tests
# ------------------------------------------------------------------------------

if(BUILD_TEST)
    add_subproject(
        bfutil test
        DEPENDS gsl
        DEPENDS json
        DEPENDS catch
        DEPENDS hippomocks
        DEPENDS bfroot
    )
endif()

#if(BUILD_TEST AND NOT WIN32)
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

if(BUILD_TEST)
    add_subproject(
        bfm test
        DEPENDS bfroot
    )

    add_subproject(
        bfruntime test
        DEPENDS bfroot
    )

    add_subproject(
        bfvmm test
        DEPENDS bfroot
    )
endif()

# ------------------------------------------------------------------------------
# Userspace Components
# ------------------------------------------------------------------------------

if(BUILD_USERSPACE)
    add_subproject(
        bfutil userspace
        DEPENDS bfroot
    )
    add_subproject(
        bfintrinsics userspace
        DEPENDS gsl
        DEPENDS json
        DEPENDS bfroot
    )
    add_subproject(
        bfm userspace
        DEPENDS gsl
        DEPENDS json
        DEPENDS cxxopts
        DEPENDS bfroot
    )
endif()

# ------------------------------------------------------------------------------
# External Components
# ------------------------------------------------------------------------------

include_external_extensions()

# ------------------------------------------------------------------------------
# EFI Components
# ------------------------------------------------------------------------------

if(BUILD_EFI AND NOT WIN32)
    include_dependency(SOURCE_DEPENDS_DIR gnuefi)

    add_subproject(
        bfefi efi
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
