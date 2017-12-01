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
# Cmake global properties
# ------------------------------------------------------------------------------

include(${CMAKE_SOURCE_DIR}/scripts/cmake/global_vars.cmake)
include(${CMAKE_SOURCE_DIR}/scripts/cmake/macros.cmake)
include(${BF_CONFIG_DIR}/default.cmake)
include(${BF_FLAGS_DIR}/flags.cmake)
include(${BF_SCRIPTS_DIR}/cmake/build_rules.cmake)
include(${BF_SCRIPTS_DIR}/cmake/targets.cmake)
include(ExternalProject)

validate_build()

if(ENABLE_DEPEND_UPDATES)
    set_property(GLOBAL PROPERTY EP_UPDATE_DISCONNECTED OFF)
else()
    set_property(GLOBAL PROPERTY EP_UPDATE_DISCONNECTED ON)
endif()

if(NOT ${BUILD_VERBOSE})
    set_property(GLOBAL PROPERTY TARGET_MESSAGES OFF)
endif()

set(CMAKE_PREFIX_PATH ${BF_BUILD_INSTALL_DIR})

# ------------------------------------------------------------------------------
# Toolchain components
# ------------------------------------------------------------------------------

include(${BF_DEPENDS_DIR}/python.cmake)
include(${BF_DEPENDS_DIR}/git.cmake)
include(${BF_DEPENDS_DIR}/gsl.cmake)
include(${BF_DEPENDS_DIR}/json.cmake)

add_subproject(
    SOURCE_DIR ${BF_SOURCE_DIR}/bfsdk
    TARGET bfsdk
    TOOLCHAIN ${TOOLCHAIN_PATH_BFSDK}
    DEPENDS gsl json
)

if(${BUILD_TARGET_ARCH} STREQUAL "x86_64")
    include(${BF_DEPENDS_DIR}/nasm.cmake)
endif()

if(ENABLE_ASTYLE)
    include(${BF_DEPENDS_DIR}/astyle.cmake)
endif()

if(ENABLE_TIDY)
    include(${BF_DEPENDS_DIR}/clang_tidy.cmake)
endif()

if(ENABLE_UNITTESTING)
    include(${BF_DEPENDS_DIR}/catch.cmake)
    include(${BF_DEPENDS_DIR}/hippomocks.cmake)
    add_dependencies(bfsdk catch hippomocks)
endif()

# ------------------------------------------------------------------------------
# VMM Components
# ------------------------------------------------------------------------------

if(${BUILD_VMM})
    include(${BF_DEPENDS_DIR}/binutils.cmake)
    include(${BF_DEPENDS_DIR}/newlib.cmake)
    include(${BF_DEPENDS_DIR}/llvm.cmake)
    include(${BF_DEPENDS_DIR}/libcxx_download.cmake)
    include(${BF_DEPENDS_DIR}/libcxxabi.cmake)
    include(${BF_DEPENDS_DIR}/libcxx.cmake)

    add_subproject(
        SOURCE_DIR ${BF_SOURCE_DIR}/bfsysroot/bfunwind
        TARGET bfunwind
        TOOLCHAIN ${TOOLCHAIN_PATH_BFUNWIND}
        DEPENDS bfsdk binutils newlib
    )

    add_subproject(
        SOURCE_DIR ${BF_SOURCE_DIR}/bfsysroot/bfsupport
        TARGET bfsupport
        TOOLCHAIN ${TOOLCHAIN_PATH_BFSUPPORT}
        DEPENDS bfsdk binutils libcxx libcxxabi newlib gsl
    )

    add_subproject(
        SOURCE_DIR ${BF_SOURCE_DIR}/bfvmm
        TARGET bfvmm
        TOOLCHAIN ${TOOLCHAIN_PATH_BFVMM}
        DEPENDS bfsdk binutils bfunwind bfsupport
    )
endif()

# ------------------------------------------------------------------------------
# OS Components
# ------------------------------------------------------------------------------

if(${BUILD_BFELF_LOADER})
    add_subproject(
        SOURCE_DIR ${BF_SOURCE_DIR}/bfelf_loader
        TARGET bfelf_loader
        TOOLCHAIN ${TOOLCHAIN_PATH_BFELF_LOADER}
        DEPENDS bfsdk
    )
endif()

if(${BUILD_BFDRIVER})
    add_subproject(
        SOURCE_DIR ${BF_SOURCE_DIR}/bfdriver
        TARGET bfdriver
        TOOLCHAIN ${TOOLCHAIN_PATH_BFDRIVER}
        DEPENDS bfsdk bfelf_loader
    )
endif()

if(${BUILD_BFM})
    add_subproject(
        SOURCE_DIR ${BF_SOURCE_DIR}/bfm
        TARGET bfm
        TOOLCHAIN ${TOOLCHAIN_PATH_BFM}
        DEPENDS bfsdk bfelf_loader gsl json
    )
endif()

# ------------------------------------------------------------------------------
# Extended APIs
# ------------------------------------------------------------------------------

if(${BUILD_EXTENDED_APIS})
    add_subproject(
        SOURCE_DIR ${EXTENDED_APIS_PATH}
        TARGET extended_apis
        TOOLCHAIN ${TOOLCHAIN_PATH_EXTENDED_APIS}
        DEPENDS bfsdk binutils bfvmm
    )
endif()

# ------------------------------------------------------------------------------
# Unit Tests
# ------------------------------------------------------------------------------

if(ENABLE_UNITTESTING)
    add_subproject(
        SOURCE_DIR ${BF_SOURCE_DIR}/bfsdk/tests
        TARGET bfsdk_test
        TOOLCHAIN ${TOOLCHAIN_PATH_UNITTEST}
        DEPENDS bfsdk
    )

    if(${UNITTEST_BFDRIVER})
        add_subproject(
            SOURCE_DIR ${BF_SOURCE_DIR}/bfdriver/tests
            TARGET bfdriver_test
            TOOLCHAIN ${TOOLCHAIN_PATH_UNITTEST}
            DEPENDS bfsdk bfsdk_test bfelf_loader bfvmm
        )
    endif()

    if(${UNITTEST_BFELF_LOADER})
        add_subproject(
            SOURCE_DIR ${BF_SOURCE_DIR}/bfelf_loader/tests
            TARGET bfelf_loader_test
            TOOLCHAIN ${TOOLCHAIN_PATH_UNITTEST}
            DEPENDS bfsdk bfsdk_test bfvmm
        )
    endif()

    if(${UNITTEST_BFM})
        add_subproject(
            SOURCE_DIR ${BF_SOURCE_DIR}/bfm/tests
            TARGET bfm_test
            TOOLCHAIN ${TOOLCHAIN_PATH_UNITTEST}
            DEPENDS bfsdk bfsdk_test
        )
    endif()

    if(${UNITTEST_BFSUPPORT})
        add_subproject(
            SOURCE_DIR ${BF_SOURCE_DIR}/bfsysroot/bfsupport/tests
            TARGET bfsupport_test
            TOOLCHAIN ${TOOLCHAIN_PATH_UNITTEST}
            DEPENDS bfsdk bfsdk_test
        )
    endif()

    if(${UNITTEST_VMM})
        add_subproject(
            SOURCE_DIR ${BF_SOURCE_DIR}/bfvmm/test
            TARGET bfvmm_test
            TOOLCHAIN ${TOOLCHAIN_PATH_UNITTEST}
            DEPENDS bfsdk bfsdk_test
        )
    endif()

    if(${UNITTEST_EXTENDED_APIS})
        add_subproject(
            SOURCE_DIR ${EXTENDED_APIS_PATH}/tests
            TARGET extended_apis_test
            TOOLCHAIN ${TOOLCHAIN_PATH_UNITTEST}
            DEPENDS bfsdk bfsdk_test bfvmm_test
        )
    endif()
endif()

print_banner()
print_usage()
