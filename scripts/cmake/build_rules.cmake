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

# ------------------------------------------------------------------------------
# General build rules
# ------------------------------------------------------------------------------

add_build_rule(
    FAIL_ON ${BUILD_VMM} AND NOT ${BUILD_VMM_SHARED} AND NOT ${BUILD_VMM_STATIC}
    FAIL_MSG "Must enable either BUILD_VMM_SHARED or BUILD_VMM_STATIC when building VMM components"
)

add_build_rule(
    FAIL_ON ${BUILD_BFDRIVER} AND NOT ${BUILD_BFELF_LOADER}
    FAIL_MSG "Cannot build the Bareflank driver without building the Bareflank elf loader, enable BUILD_BFELF_LOADER"
)

add_build_rule(
    FAIL_ON ${BUILD_BFM} AND NOT ${BUILD_BFELF_LOADER}
    FAIL_MSG "Cannot build bfm without building the Bareflank elf loader, enable BUILD_BFELF_LOADER"
)

add_build_rule(
    FAIL_ON NOT ${BUILD_VMM} AND ${BUILD_EXTENDED_APIS}
    FAIL_MSG "Cannot build the Bareflank Extended APIs without building VMM components, enable BUILD_VMM"
)

# Allow advanced users to specify alternative VMM toolchains, but block
# architecture-specific ones that do not match the target.
add_build_rule(
    FAIL_ON (${TOOLCHAIN_PATH_VMM} MATCHES "clang_.*vmm_elf.cmake$") AND NOT
        (${TOOLCHAIN_PATH_VMM} MATCHES "clang_${BUILD_TARGET_ARCH}_vmm_elf.cmake")
    FAIL_MSG "Cannot build bfvmm with a toolchain for the wrong architecture"
)

# ------------------------------------------------------------------------------
# Unit testing build rules
# ------------------------------------------------------------------------------

add_build_rule(
    FAIL_ON ${UNITTEST_BFDRIVER} AND NOT ${BUILD_VMM}
    FAIL_MSG "Shared library VMM components are required for driver unit tests, please enable BUILD_VMM and BUILD_VMM_SHARED"
)

add_build_rule(
    FAIL_ON ${UNITTEST_BFDRIVER} AND NOT ${BUILD_VMM_SHARED}
    FAIL_MSG "Shared library VMM components are required for driver unit tests, please enable BUILD_VMM and BUILD_VMM_SHARED"
)

add_build_rule(
    FAIL_ON ${UNITTEST_BFDRIVER} AND NOT ${BUILD_BFELF_LOADER}
    FAIL_MSG "The Bareflank elf loader is required for driver unit tests, please enable BUILD_BFELF_LOADER"
)

add_build_rule(
    FAIL_ON ${UNITTEST_BFELF_LOADER} AND NOT ${BUILD_VMM}
    FAIL_MSG "Shared library VMM components are required for elf loader unit tests, please enable BUILD_VMM and BUILD_VMM_SHARED"
)

add_build_rule(
    FAIL_ON ${UNITTEST_BFELF_LOADER} AND NOT ${BUILD_VMM_SHARED}
    FAIL_MSG "Shared library VMM components are required for elf loader unit tests, please enable BUILD_VMM and BUILD_VMM_SHARED"
)

add_build_rule(
    FAIL_ON ${UNITTEST_EXTENDED_APIS} AND NOT ${UNITTEST_VMM}
    FAIL_MSG "Extended APIs unit tests require VMM unit tests, please enable UNITTEST_VMM"
)

# ------------------------------------------------------------------------------
# Developer-mode build rules
# ------------------------------------------------------------------------------

add_build_rule(
    FAIL_ON ${ENABLE_DEVELOPER_MODE} AND NOT ${ENABLE_UNITTESTING}
    FAIL_MSG "Unit testing must be enabled while building in developer mode, please set ENABLE_UNITTESTING=ON or ENABLE_DEVELOPER_MODE=OFF"
)

add_build_rule(
    FAIL_ON ${ENABLE_DEVELOPER_MODE} AND NOT ${ENABLE_ASTYLE}
    FAIL_MSG "Astyle must be enabled while building in developer mode, please set ENABLE_ASTYLE=ON or ENABLE_DEVELOPER_MODE=OFF"
)

add_build_rule(
    FAIL_ON ${ENABLE_DEVELOPER_MODE} AND NOT ${ENABLE_TIDY}
    FAIL_MSG "Clang-tidy must be enabled while building in developer mode, please set ENABLE_TIDY=ON or ENABLE_DEVELOPER_MODE=OFF"
)

# ------------------------------------------------------------------------------
# Windows build rules
# ------------------------------------------------------------------------------

set(_ON_WINDOWS ${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Windows" CACHE INTERNAL "")
add_build_rule(
    FAIL_ON  ${_ON_WINDOWS} AND ${ENABLE_UNITTESTING}
    FAIL_MSG "Unit testing is not supported on Windows"
)

add_build_rule(
    FAIL_ON  ${_ON_WINDOWS} AND ${BUILD_VMM}
    FAIL_MSG "Building VMM components from Windows is not supported"
)

add_build_rule(
    FAIL_ON  ${_ON_WINDOWS} AND ${ENABLE_CODECOV}
    FAIL_MSG "Code coverage is not supported on Windows"
)

add_build_rule(
    FAIL_ON  ${_ON_WINDOWS} AND ${ENABLE_TIDY}
    FAIL_MSG "Clang-tidy is not supported on Windows"
)

# ------------------------------------------------------------------------------
# Linux build rules
# ------------------------------------------------------------------------------

set(_ON_LINUX ${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Linux" CACHE INTERNAL "")
add_build_rule(
    FAIL_ON  ${_ON_LINUX} AND ${BUILD_TARGET_OS} STREQUAL "Windows"
    FAIL_MSG "Building Windows components from Linux is not supported, please set BUILD_TARGET_OS to Linux"
)
