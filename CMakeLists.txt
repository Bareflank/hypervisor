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
# Config / Targets
# ------------------------------------------------------------------------------

include(scripts/cmake/config/default.cmake)
include_external_config()

# ------------------------------------------------------------------------------
# BFM VMM
# ------------------------------------------------------------------------------

set_bfm_vmm(${DEFAULT_VMM} DEFAULT)
message(STATUS "Bareflank Manager VMM: ${BFM_VMM}")

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

include(scripts/cmake/targets.cmake)

# ------------------------------------------------------------------------------
# Dependencies
# ------------------------------------------------------------------------------

include_dependency(gsl)
include_dependency(json)
include_dependency(astyle)
include_dependency(clang_tidy)
include_dependency(catch)
include_dependency(hippomocks)
include_dependency(python)
include_dependency(binutils)
include_dependency(newlib)
include_dependency(llvm)
include_dependency(libcxxabi)
include_dependency(libcxx)

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

if(ENABLE_BUILD_VMM OR (ENABLE_BUILD_TEST AND NOT WIN32))
    add_subproject(
        bfunwind vmm
        DEPENDS libcxx
    )

    add_subproject(
        bfruntime vmm
        DEPENDS libcxx gsl
    )
endif()

if(ENABLE_BUILD_VMM)
    add_subproject(
        bfintrinsics vmm
        DEPENDS binutils
    )

    add_subproject(
        bfvmm vmm
        DEPENDS bfunwind bfruntime gsl
    )

    add_subproject(
        bfvmm_main vmm
        DEPENDS bfvmm bfintrinsics
        SOURCE_DIR ${SOURCE_BFVMM_DIR}/src/main
    )
endif()

# ------------------------------------------------------------------------------
# Unit Tests
# ------------------------------------------------------------------------------

if(ENABLE_BUILD_TEST)
    add_subproject(
        bfsdk test
        DEPENDS gsl json catch hippomocks
    )
endif()

if(ENABLE_BUILD_TEST AND NOT WIN32)
    add_subproject(
        bfdummy vmm
        TOOLCHAIN ${VMM_TEST_TOOLCHAIN_PATH}
        DEPENDS bfunwind bfruntime gsl
    )

    add_subproject(
        bfdummy_main vmm
        TOOLCHAIN ${VMM_TEST_TOOLCHAIN_PATH}
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
        bfintrinsics test
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
        bfm userspace
        DEPENDS json gsl
    )
endif()

# ------------------------------------------------------------------------------
# External Components
# ------------------------------------------------------------------------------

include_external_extensions()

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
