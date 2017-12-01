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
# README
# ------------------------------------------------------------------------------

# This file defines all CONFIGURABLE cmake variables set to their default value.
# These variables are configurable through cmake-gui and ccmake.
# To override the default settings, you can specify an alternate config file
# using: cmake /path/to/src -DBFCONFIG=/path/to/config.cmake

# ------------------------------------------------------------------------------
# Import user configuration file (if specified)
# ------------------------------------------------------------------------------

if(BFCONFIG)
    find_file(_BFCONFIG_PATH ${BFCONFIG} ${BF_CONFIG_DIR})
    set(_BFCONFIG_PATH ${_BFCONFIG_PATH} CACHE INTERNAL "")
    if(EXISTS ${_BFCONFIG_PATH})
        message(STATUS "Configuring Bareflank using: ${_BFCONFIG_PATH}")
        include(${_BFCONFIG_PATH})
    else()
        message(FATAL_ERROR "Configuration file ${BFCONFIG} not found")
    endif()
else()
    message(STATUS "No configuration specified, using default settings")
endif()

# ------------------------------------------------------------------------------
# Build attributes
# ------------------------------------------------------------------------------

set(_BUILD_TYPE_DEFAULT "Release" CACHE INTERNAL "")
if(CMAKE_BUILD_TYPE)
    set(_BUILD_TYPE_DEFAULT ${CMAKE_BUILD_TYPE})
endif()
set(_BUILD_TYPE_DEFAULT ${CMAKE_BUILD_TYPE})
add_config(
    CONFIG_NAME BUILD_TYPE
    CONFIG_TYPE STRING
    DEFAULT_VAL ${_BUILD_TYPE_DEFAULT}
    DESCRIPTION "The type of build"
    OPTIONS Release Debug
)

set(_TARGET_ARCH_DEFAULT ${CMAKE_HOST_SYSTEM_PROCESSOR} CACHE INTERNAL "")
# Cmake + Windows sets CMAKE_HOST_SYSTEM_PROCESSOR to 'AMD64' instead of 'x86_64'
if(${_TARGET_ARCH_DEFAULT} STREQUAL "AMD64")
    set(_TARGET_ARCH_DEFAULT "x86_64")
endif()
add_config(
    CONFIG_NAME BUILD_TARGET_ARCH
    CONFIG_TYPE STRING
    DEFAULT_VAL ${_TARGET_ARCH_DEFAULT}
    DESCRIPTION "The target architecture for the build"
    OPTIONS x86_64 aarch64
)

set(_TARGET_OS_DEFAULT ${CMAKE_HOST_SYSTEM_NAME} CACHE INTERNAL "")
if(_TARGET_OS_DEFAULT STREQUAL "CYGWIN")
    set(_TARGET_OS_DEFAULT "Windows")
endif()
add_config(
    CONFIG_NAME BUILD_TARGET_OS
    CONFIG_TYPE STRING
    DEFAULT_VAL ${_TARGET_OS_DEFAULT}
    DESCRIPTION "The target operating system for the build"
    OPTIONS Linux Windows
)

add_config(
    CONFIG_NAME BUILD_VMM
    CONFIG_TYPE BOOL
    DEFAULT_VAL ON
    DESCRIPTION "Include VMM components in this build"
)

add_config(
    CONFIG_NAME BUILD_VMM_SHARED
    CONFIG_TYPE BOOL
    DEFAULT_VAL ON
    DESCRIPTION "Build VMM components as shared libraries"
)

add_config(
    CONFIG_NAME BUILD_VMM_STATIC
    CONFIG_TYPE BOOL
    DEFAULT_VAL OFF
    DESCRIPTION "Build VMM components as static libraries"
)

add_config(
    CONFIG_NAME BUILD_BFELF_LOADER
    CONFIG_TYPE BOOL
    DEFAULT_VAL ON
    DESCRIPTION "Include the Bareflank elf loader in this build"
)

add_config(
    CONFIG_NAME BUILD_BFDRIVER
    CONFIG_TYPE BOOL
    DEFAULT_VAL ON
    DESCRIPTION "Include the Bareflank driver in this build"
)

add_config(
    CONFIG_NAME BUILD_BFM
    CONFIG_TYPE BOOL
    DEFAULT_VAL ON
    DESCRIPTION "Include the Bareflank Manager utility in this build"
)

add_config(
    CONFIG_NAME BUILD_EXTENDED_APIS
    CONFIG_TYPE BOOL
    DEFAULT_VAL OFF
    DESCRIPTION "Include the Bareflank Extended APIs in this build"
)

add_config(
    CONFIG_NAME EXTENDED_APIS_PATH
    CONFIG_TYPE PATH
    DEFAULT_VAL ${BF_SOURCE_DIR}/extended_apis
    DESCRIPTION "Path to the Bareflank Extended APIs"
)

if(${CMAKE_VERBOSE_MAKEFILE})
    set(_BUILD_VERBOSE ON CACHE INTERNAL "")
else()
    set(_BUILD_VERBOSE OFF CACHE INTERNAL "")
endif()
add_config(
    CONFIG_NAME BUILD_VERBOSE
    CONFIG_TYPE BOOL
    DEFAULT_VAL ${_BUILD_VERBOSE}
    DESCRIPTION "Display verbose output during build"
)

STRING(TOLOWER "${BF_BUILD_INSTALL_DIR}/${BUILD_TARGET_OS}-${BUILD_TARGET_ARCH}-${BUILD_TYPE}" _BUILD_SYSROOT_OS)
set(_BUILD_SYSROOT_OS ${_BUILD_SYSROOT_OS} CACHE INTERNAL "")
add_config(
    CONFIG_NAME BUILD_SYSROOT_OS
    CONFIG_TYPE PATH
    DEFAULT_VAL ${_BUILD_SYSROOT_OS}
    DESCRIPTION "Path to userspace build-system sysroot"
)

STRING(TOLOWER "${BF_BUILD_INSTALL_DIR}/vmm-${BUILD_TARGET_ARCH}-${BUILD_TYPE}" _BUILD_SYSROOT_VMM)
set(_BUILD_SYSROOT_VMM ${_BUILD_SYSROOT_VMM} CACHE INTERNAL "")
add_config(
    CONFIG_NAME BUILD_SYSROOT_VMM
    CONFIG_TYPE PATH
    DEFAULT_VAL ${_BUILD_SYSROOT_VMM}
    DESCRIPTION "Path to vmm build-system sysroot"
)

STRING(TOLOWER "${BF_BUILD_INSTALL_DIR}/${BUILD_TARGET_OS}-${BUILD_TARGET_ARCH}-test" _BUILD_SYSROOT_TEST)
set(_BUILD_SYSROOT_TEST ${_BUILD_SYSROOT_TEST} CACHE INTERNAL "")
add_config(
    CONFIG_NAME BUILD_SYSROOT_TEST
    CONFIG_TYPE PATH
    DEFAULT_VAL ${_BUILD_SYSROOT_TEST}
    DESCRIPTION "Path to test build-system sysroot"
)

# ------------------------------------------------------------------------------
# Developer Features
# ------------------------------------------------------------------------------

add_config(
    CONFIG_NAME ENABLE_DEVELOPER_MODE
    CONFIG_TYPE BOOL
    DEFAULT_VAL OFF
    DESCRIPTION "Run unit tests, astyle format, and clang-tidy checks on every build"
)

add_config(
    CONFIG_NAME ENABLE_UNITTESTING
    CONFIG_TYPE BOOL
    DEFAULT_VAL ${ENABLE_DEVELOPER_MODE}
    DESCRIPTION "Enable unit testing"
)

add_config(
    CONFIG_NAME ENABLE_COMPILER_WARNINGS
    CONFIG_TYPE BOOL
    DEFAULT_VAL OFF
    DESCRIPTION "Enable compiler warnings"
)

add_config(
    CONFIG_NAME ENABLE_ASAN
    CONFIG_TYPE BOOL
    DEFAULT_VAL OFF
    DESCRIPTION "Enable clang AddressSanitizer"
)

add_config(
    CONFIG_NAME ENABLE_USAN
    CONFIG_TYPE BOOL
    DEFAULT_VAL OFF
    DESCRIPTION "Enable clang UndefinedBehaviorSanitizer"
)

add_config(
    CONFIG_NAME ENABLE_CODECOV
    CONFIG_TYPE BOOL
    DEFAULT_VAL OFF
    DESCRIPTION "Enable code coverage from codecov.io"
)

add_config(
    CONFIG_NAME ENABLE_TIDY
    CONFIG_TYPE BOOL
    DEFAULT_VAL ${ENABLE_DEVELOPER_MODE}
    DESCRIPTION "Enable clang-tidy"
)

add_config(
    CONFIG_NAME ENABLE_ASTYLE
    CONFIG_TYPE BOOL
    DEFAULT_VAL ${ENABLE_DEVELOPER_MODE}
    DESCRIPTION "Enable astyle formatting"
)

add_config(
    CONFIG_NAME ENABLE_DEPEND_UPDATES
    CONFIG_TYPE BOOL
    DEFAULT_VAL OFF
    DESCRIPTION "Check dependencies for updates on every build"
)

# ------------------------------------------------------------------------------
# Unit Testing
# ------------------------------------------------------------------------------

add_config(
    CONFIG_NAME UNITTEST_VMM
    CONFIG_TYPE BOOL
    DEFAULT_VAL ${ENABLE_UNITTESTING}
    DESCRIPTION "Build unit tests for the VMM"
)

set(_DEFAULT_UNITTEST_BFDRIVER OFF CACHE INTERNAL "")
if(${ENABLE_UNITTESTING} AND ${BUILD_BFDRIVER} AND ${BUILD_VMM} AND ${BUILD_VMM_SHARED})
    set(_DEFAULT_UNITTEST_BFDRIVER ON)
endif()
add_config(
    CONFIG_NAME UNITTEST_BFDRIVER
    CONFIG_TYPE BOOL
    DEFAULT_VAL ${_DEFAULT_UNITTEST_BFDRIVER}
    DESCRIPTION "Build driver unit tests"
)

set(_DEFAULT_UNITTEST_BFELF_LOADER OFF CACHE INTERNAL "")
if(${ENABLE_UNITTESTING} AND ${BUILD_BFELF_LOADER} AND ${BUILD_VMM} AND ${BUILD_VMM_SHARED})
    set(_DEFAULT_UNITTEST_BFELF_LOADER ON)
endif()
add_config(
    CONFIG_NAME UNITTEST_BFELF_LOADER
    CONFIG_TYPE BOOL
    DEFAULT_VAL ${_DEFAULT_UNITTEST_BFELF_LOADER}
    DESCRIPTION "Build elf loader unit tests"
)

set(_DEFAULT_UNITTEST_BFM OFF CACHE INTERNAL "")
if(${ENABLE_UNITTESTING} AND ${BUILD_BFM})
    set(_DEFAULT_UNITTEST_BFM ON)
endif()
add_config(
    CONFIG_NAME UNITTEST_BFM
    CONFIG_TYPE BOOL
    DEFAULT_VAL ${_DEFAULT_UNITTEST_BFM}
    DESCRIPTION "Build bfm unit tests"
)

add_config(
    CONFIG_NAME UNITTEST_BFSUPPORT
    CONFIG_TYPE BOOL
    DEFAULT_VAL ${ENABLE_UNITTESTING}
    DESCRIPTION "Build C runtime support unit tests"
)

set(_DEFAULT_UNITTEST_EAPIS OFF CACHE INTERNAL "")
if(${ENABLE_UNITTESTING} AND ${BUILD_EXTENDED_APIS})
    set(_DEFAULT_UNITTEST_EAPIS ON)
endif()
add_config(
    CONFIG_NAME UNITTEST_EXTENDED_APIS
    CONFIG_TYPE BOOL
    DEFAULT_VAL ${_DEFAULT_UNITTEST_EAPIS}
    DESCRIPTION "Build Bareflank Extended APIs unit tests"
)

# ------------------------------------------------------------------------------
# High-level cmake toolchains
# ------------------------------------------------------------------------------

add_config(
    CONFIG_NAME TOOLCHAIN_PATH_USERSPACE
    CONFIG_TYPE FILE
    DEFAULT_VAL ${BF_TOOLCHAIN_DIR}/gcc_host.cmake
    DESCRIPTION "Path to the default cmake toolchain file for building userspace components"
)

add_config(
    CONFIG_NAME TOOLCHAIN_PATH_KERNEL
    CONFIG_TYPE FILE
    DEFAULT_VAL ${BF_TOOLCHAIN_DIR}/default_kernel.cmake
    DESCRIPTION "Path to the default cmake toolchain file for building kernel components"
)

add_config(
    CONFIG_NAME TOOLCHAIN_PATH_VMM
    CONFIG_TYPE FILE
    DEFAULT_VAL ${BF_TOOLCHAIN_DIR}/clang_${BUILD_TARGET_ARCH}_vmm_elf.cmake
    DESCRIPTION "Path to the default cmake toolchain file for building vmm components"
)

add_config(
    CONFIG_NAME TOOLCHAIN_PATH_UNITTEST
    CONFIG_TYPE FILE
    DEFAULT_VAL ${TOOLCHAIN_PATH_USERSPACE}
    DESCRIPTION "Path to the default cmake toolchain file for building unit tests"
)

# ------------------------------------------------------------------------------
# Advanced (granular) cmake toolchains
# ------------------------------------------------------------------------------

add_config(
    CONFIG_NAME TOOLCHAIN_PATH_ASTYLE
    CONFIG_TYPE FILE
    DEFAULT_VAL ${TOOLCHAIN_PATH_USERSPACE}
    DESCRIPTION "Path to a cmake toolchain file for building astyle"
    ADVANCED
)

add_config(
    CONFIG_NAME TOOLCHAIN_PATH_BINUTILS
    CONFIG_TYPE FILE
    DEFAULT_VAL ${TOOLCHAIN_PATH_USERSPACE}
    DESCRIPTION "Path to a cmake toolchain file for building GNU binutils"
    ADVANCED
)

add_config(
    CONFIG_NAME TOOLCHAIN_PATH_CATCH
    CONFIG_TYPE FILE
    DEFAULT_VAL ${TOOLCHAIN_PATH_USERSPACE}
    DESCRIPTION "Path to a cmake toolchain file for building catch"
    ADVANCED
)

add_config(
    CONFIG_NAME TOOLCHAIN_PATH_EXTENDED_APIS
    CONFIG_TYPE FILE
    DEFAULT_VAL ${TOOLCHAIN_PATH_VMM}
    DESCRIPTION "Path to a cmake toolchain file for building the bareflank extended apis"
    ADVANCED
)

add_config(
    CONFIG_NAME TOOLCHAIN_PATH_GSL
    CONFIG_TYPE FILE
    DEFAULT_VAL ${TOOLCHAIN_PATH_USERSPACE}
    DESCRIPTION "Path to a cmake toolchain file for building C++ guidelines support library"
    ADVANCED
)

add_config(
    CONFIG_NAME TOOLCHAIN_PATH_HIPPOMOCKS
    CONFIG_TYPE FILE
    DEFAULT_VAL ${TOOLCHAIN_PATH_USERSPACE}
    DESCRIPTION "Path to a cmake toolchain file for building hippomocks"
    ADVANCED
)

add_config(
    CONFIG_NAME TOOLCHAIN_PATH_JSON
    CONFIG_TYPE FILE
    DEFAULT_VAL ${TOOLCHAIN_PATH_USERSPACE}
    DESCRIPTION "Path to a cmake toolchain file for building JSON"
    ADVANCED
)

add_config(
    CONFIG_NAME TOOLCHAIN_PATH_LIBCXX
    CONFIG_TYPE FILE
    DEFAULT_VAL ${TOOLCHAIN_PATH_VMM}
    DESCRIPTION "Path to a cmake toolchain file for building libc++"
    ADVANCED
)

add_config(
    CONFIG_NAME TOOLCHAIN_PATH_LIBCXXABI
    CONFIG_TYPE FILE
    DEFAULT_VAL ${TOOLCHAIN_PATH_VMM}
    DESCRIPTION "Path to a cmake toolchain file for building libc++abi"
    ADVANCED
)

add_config(
    CONFIG_NAME TOOLCHAIN_PATH_BFDRIVER
    CONFIG_TYPE FILE
    DEFAULT_VAL ${TOOLCHAIN_PATH_KERNEL}
    DESCRIPTION "Path to a cmake toolchain file for building bfdriver"
    ADVANCED
)

add_config(
    CONFIG_NAME TOOLCHAIN_PATH_BFELF_LOADER
    CONFIG_TYPE FILE
    DEFAULT_VAL ${TOOLCHAIN_PATH_USERSPACE}
    DESCRIPTION "Path to a cmake toolchain file for building bfelf_loader"
    ADVANCED
)

add_config(
    CONFIG_NAME TOOLCHAIN_PATH_BFM
    CONFIG_TYPE FILE
    DEFAULT_VAL ${TOOLCHAIN_PATH_USERSPACE}
    DESCRIPTION "Path to a cmake toolchain file for building bfm"
    ADVANCED
)

add_config(
    CONFIG_NAME TOOLCHAIN_PATH_BFSDK
    CONFIG_TYPE FILE
    DEFAULT_VAL ${TOOLCHAIN_PATH_USERSPACE}
    DESCRIPTION "Path to a cmake toolchain file for building bfsdk"
    ADVANCED
)

add_config(
    CONFIG_NAME TOOLCHAIN_PATH_BFSYSROOT
    CONFIG_TYPE FILE
    DEFAULT_VAL ${TOOLCHAIN_PATH_VMM}
    DESCRIPTION "Path to a cmake toolchain file for building bfsysroot"
    ADVANCED
)

add_config(
    CONFIG_NAME TOOLCHAIN_PATH_BFSUPPORT
    CONFIG_TYPE FILE
    DEFAULT_VAL ${TOOLCHAIN_PATH_VMM}
    DESCRIPTION "Path to a cmake toolchain file for building bfsupport"
    ADVANCED
)

add_config(
    CONFIG_NAME TOOLCHAIN_PATH_BFUNWIND
    CONFIG_TYPE FILE
    DEFAULT_VAL ${TOOLCHAIN_PATH_VMM}
    DESCRIPTION "Path to a cmake toolchain file for building bfunwind"
    ADVANCED
)

add_config(
    CONFIG_NAME TOOLCHAIN_PATH_BFVMM
    CONFIG_TYPE FILE
    DEFAULT_VAL ${TOOLCHAIN_PATH_VMM}
    DESCRIPTION "Path to a cmake toolchain file for building bfvmm"
    ADVANCED
)

# ------------------------------------------------------------------------------
# Non-cmake toolchains
# ------------------------------------------------------------------------------

add_config(
    CONFIG_NAME TOOLCHAIN_NEWLIB_CC
    CONFIG_TYPE FILE
    DEFAULT_VAL ${BUILD_SYSROOT_VMM}/bin/${BUILD_TARGET_ARCH}-vmm-clang
    DESCRIPTION "Path to compiler for building newlib"
    SKIP_VALIDATION
    ADVANCED
)

add_config(
    CONFIG_NAME TOOLCHAIN_NEWLIB_AS
    CONFIG_TYPE FILE
    DEFAULT_VAL ${BUILD_SYSROOT_VMM}/bin/${BUILD_TARGET_ARCH}-vmm-elf-as
    DESCRIPTION "Path to an assembler for building newlib"
    SKIP_VALIDATION
    ADVANCED
)

add_config(
    CONFIG_NAME TOOLCHAIN_NEWLIB_AR
    CONFIG_TYPE FILE
    DEFAULT_VAL ${BUILD_SYSROOT_VMM}/bin/${BUILD_TARGET_ARCH}-vmm-elf-ar
    DESCRIPTION "Path to binutils archiver for building newlib"
    SKIP_VALIDATION
    ADVANCED
)

add_config(
    CONFIG_NAME TOOLCHAIN_NEWLIB_RANLIB
    CONFIG_TYPE FILE
    DEFAULT_VAL ${BUILD_SYSROOT_VMM}/bin/${BUILD_TARGET_ARCH}-vmm-elf-ranlib
    DESCRIPTION "Path to binutils ranlib for building newlib"
    SKIP_VALIDATION
    ADVANCED
)

# ------------------------------------------------------------------------------
# Compiler Flags
# ------------------------------------------------------------------------------

add_config(
    CONFIG_NAME C_FLAGS_VMM
    CONFIG_TYPE STRING
    DEFAULT_VAL ""
    DESCRIPTION "Additional C compiler flags for VMM components"
)

add_config(
    CONFIG_NAME CXX_FLAGS_VMM
    CONFIG_TYPE STRING
    DEFAULT_VAL ""
    DESCRIPTION "Additional C++ compiler flags for VMM components"
)

add_config(
    CONFIG_NAME C_FLAGS_USERSPACE
    CONFIG_TYPE STRING
    DEFAULT_VAL ""
    DESCRIPTION "Additional C compiler flags for userspace components"
)

add_config(
    CONFIG_NAME CXX_FLAGS_USERSPACE
    CONFIG_TYPE STRING
    DEFAULT_VAL ""
    DESCRIPTION "Additional C++ compiler flags for userspace components"
)

# ------------------------------------------------------------------------------
# BFM Configs
# ------------------------------------------------------------------------------

add_config(
    CONFIG_NAME BFM_VMM_BIN_PATH
    CONFIG_TYPE PATH
    DEFAULT_VAL ${BUILD_SYSROOT_VMM}/bin
    DESCRIPTION "Default path to vmm binaries to be loaded by bfm"
    SKIP_VALIDATION
)

add_config(
    CONFIG_NAME BFM_VMM_LIB_PATH
    CONFIG_TYPE PATH
    DEFAULT_VAL ${BUILD_SYSROOT_VMM}/lib
    DESCRIPTION "Default path to vmm libraries to be loaded by bfm"
    SKIP_VALIDATION
)

if(BUILD_VMM_SHARED AND BUILD_EXTENDED_APIS)
    set(_BFM_DEFAULT_VMM_NAME "eapis_shared")
elseif(BUILD_VMM_STATIC AND BUILD_EXTENDED_APIS)
    set(_BFM_DEFAULT_VMM_NAME "eapis_static")
elseif(BUILD_VMM_STATIC)
    set(_BFM_DEFAULT_VMM_NAME "bfvmm_static")
else()
    set(_BFM_DEFAULT_VMM_NAME "bfvmm_shared")
endif()
add_config(
    CONFIG_NAME BFM_DEFAULT_VMM
    CONFIG_TYPE FILE
    DEFAULT_VAL ${_BFM_DEFAULT_VMM_NAME}
    DESCRIPTION "Name of the default vmm to be loaded by bfm when no vmm is specified"
    SKIP_VALIDATION
)
