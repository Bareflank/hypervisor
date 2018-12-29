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
    add_subproject(
        bfdriver none
        NOBUILD
    )
endif()

# ------------------------------------------------------------------------------
# VMM Components
# ------------------------------------------------------------------------------

add_subproject(bfsdk vmm SOURCE_DIR ${SOURCE_BFSDK_DIR})
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
        SOURCE_DIR ${SOURCE_BFRUNTIME_DIR}/src/unwind
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
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfvmm/main/
    )

    add_subproject(
        integration vmm
        DEPENDS bfvmm
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfvmm/integration/
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
        DEPENDS cxxopts
    )

    add_subproject(
        bfack userspace
        DEPENDS bfintrinsics
    )
endif()

# ------------------------------------------------------------------------------
# Examples
# ------------------------------------------------------------------------------

include(examples/cpuidcount/CMakeLists.txt)
include(examples/hook/CMakeLists.txt)
include(examples/rdtsc/CMakeLists.txt)
include(examples/vpid/CMakeLists.txt)

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
