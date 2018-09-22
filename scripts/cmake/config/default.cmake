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

include(${CMAKE_SOURCE_DIR}/scripts/cmake/macros.cmake)

# ------------------------------------------------------------------------------
# Quirks
# ------------------------------------------------------------------------------

if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
    set(HOST_FORMAT_TYPE "pe" CACHE INTERNAL "")
    set(HOST_SYSTEM_NAME "Windows" CACHE INTERNAL "")
    set(OSTYPE "WIN64" CACHE INTERNAL "")
    set(ABITYPE "MS64" CACHE INTERNAL "")
elseif(CMAKE_HOST_SYSTEM_NAME STREQUAL "CYGWIN")
    set(HOST_FORMAT_TYPE "pe" CACHE INTERNAL "")
    set(HOST_SYSTEM_NAME "Windows" CACHE INTERNAL "")
    set(OSTYPE "WIN64" CACHE INTERNAL "")
    set(ABITYPE "MS64" CACHE INTERNAL "")
else()
    set(HOST_FORMAT_TYPE "elf" CACHE INTERNAL "")
    set(HOST_SYSTEM_NAME "Linux" CACHE INTERNAL "")
    set(OSTYPE "UNIX" CACHE INTERNAL "")
    set(ABITYPE "SYSV" CACHE INTERNAL "")
endif()

if(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL "x86_64")
    set(HOST_SYSTEM_PROCESSOR "x86_64" CACHE INTERNAL "")
elseif(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL "AMD64")
    set(HOST_SYSTEM_PROCESSOR "x86_64" CACHE INTERNAL "")
else()
    set(HOST_SYSTEM_PROCESSOR "unknown" CACHE INTERNAL "")
endif()

ProcessorCount(HOST_NUMBER_CORES)

# ------------------------------------------------------------------------------
# Build Command
# ------------------------------------------------------------------------------

if(CMAKE_GENERATOR STREQUAL "Unix Makefiles")
    set(BUILD_COMMAND "make")
elseif(CMAKE_GENERATOR STREQUAL "Ninja")
    set(BUILD_COMMAND "ninja")
elseif(CMAKE_GENERATOR STREQUAL "NMake")
    set(BUILD_COMMAND "nmake")
elseif(CMAKE_GENERATOR STREQUAL "Visual Studio 14 2015 Win64")
    set(BUILD_COMMAND "msbuild hypervisor.sln")
elseif(CMAKE_GENERATOR STREQUAL "Visual Studio 15 2017 Win64")
    set(BUILD_COMMAND "msbuild hypervisor.sln")
else()
    message(FATAL_ERROR "Unsupported cmake generator: ${CMAKE_GENERATOR}")
endif()

# ------------------------------------------------------------------------------
# Source Tree
# ------------------------------------------------------------------------------

set(SOURCE_ROOT_DIR ${CMAKE_SOURCE_DIR}
    CACHE INTERNAL
    "Source root direfctory"
)

set(SOURCE_CMAKE_DIR ${CMAKE_SOURCE_DIR}/scripts/cmake
    CACHE INTERNAL
    "Cmake directory"
)

set(SOURCE_CONFIG_DIR ${CMAKE_SOURCE_DIR}/scripts/cmake/config
    CACHE INTERNAL
    "Cmake configurations directory"
)

set(SOURCE_DEPENDS_DIR ${CMAKE_SOURCE_DIR}/scripts/cmake/depends
    CACHE INTERNAL
    "Cmake dependencies directory"
)

set(SOURCE_FLAGS_DIR ${CMAKE_SOURCE_DIR}/scripts/cmake/flags
    CACHE INTERNAL
    "Cmake compiler flags directory"
)

set(SOURCE_TOOLCHAIN_DIR ${CMAKE_SOURCE_DIR}/scripts/cmake/toolchain
    CACHE INTERNAL
    "Cmake toolchain files directory"
)

set(SOURCE_UTIL_DIR ${CMAKE_SOURCE_DIR}/scripts/util
    CACHE INTERNAL
    "Utility directory"
)

set(SOURCE_BFDRIVER_DIR ${CMAKE_SOURCE_DIR}/bfdriver
    CACHE INTERNAL
    "bfdriver source dir"
)

set(SOURCE_BFDUMMY_DIR ${CMAKE_SOURCE_DIR}/bfdummy
    CACHE INTERNAL
    "bfdummy source dir"
)

set(SOURCE_BFELF_LOADER_DIR ${CMAKE_SOURCE_DIR}/bfelf_loader
    CACHE INTERNAL
    "bfelf_loader source dir"
)

set(SOURCE_BFINTRINSICS_DIR ${CMAKE_SOURCE_DIR}/bfintrinsics
    CACHE INTERNAL
    "bfintrinsics source dir"
)

set(SOURCE_BFM_DIR ${CMAKE_SOURCE_DIR}/bfm
    CACHE INTERNAL
    "bfm source dir"
)

set(SOURCE_BFRUNTIME_DIR ${CMAKE_SOURCE_DIR}/bfruntime
    CACHE INTERNAL
    "bfruntime source dir"
)

set(SOURCE_BFSDK_DIR ${CMAKE_SOURCE_DIR}/bfsdk
    CACHE INTERNAL
    "bfsdk source dir"
)

set(SOURCE_BFUNWIND_DIR ${CMAKE_SOURCE_DIR}/bfunwind
    CACHE INTERNAL
    "bfunwind source dir"
)

set(SOURCE_BFVMM_DIR ${CMAKE_SOURCE_DIR}/bfvmm
    CACHE INTERNAL
    "bfvmm source dir"
)

# ------------------------------------------------------------------------------
# Build Tree
# ------------------------------------------------------------------------------

set(BUILD_ROOT_DIR ${CMAKE_BINARY_DIR}
    CACHE INTERNAL
    "Build root directory"
)

set(BUILD_BFDRIVER_DIR ${CMAKE_BINARY_DIR}/bfdriver
    CACHE INTERNAL
    "bfdriver build dir"
)

set(BUILD_BFDUMMY_DIR ${CMAKE_BINARY_DIR}/bfdummy
    CACHE INTERNAL
    "bfdummy build dir"
)

set(BUILD_BFDUMMY_MAIN_DIR ${CMAKE_BINARY_DIR}/bfdummy_main
    CACHE INTERNAL
    "bfdummy main build dir"
)

set(BUILD_BFELF_LOADER_DIR ${CMAKE_BINARY_DIR}/bfelf_loader
    CACHE INTERNAL
    "bfelf_loader build dir"
)

set(BUILD_BFINTRINSICS_DIR ${CMAKE_BINARY_DIR}/bfintrinsics
    CACHE INTERNAL
    "bfintrinsics build dir"
)

set(BUILD_BFM_DIR ${CMAKE_BINARY_DIR}/bfm
    CACHE INTERNAL
    "bfm build dir"
)

set(BUILD_BFRUNTIME_DIR ${CMAKE_BINARY_DIR}/bfruntime
    CACHE INTERNAL
    "bfruntime build dir"
)

set(BUILD_BFSDK_DIR ${CMAKE_BINARY_DIR}/bfsdk
    CACHE INTERNAL
    "bfsdk build dir"
)

set(BUILD_BFUNWIND_DIR ${CMAKE_BINARY_DIR}/bfunwind
    CACHE INTERNAL
    "bfunwind build dir"
)

set(BUILD_BFVMM_DIR ${CMAKE_BINARY_DIR}/bfvmm
    CACHE INTERNAL
    "bfvmm build dir"
)

set(BUILD_BFVMM_MAIN_DIR ${CMAKE_BINARY_DIR}/bfvmm_main
    CACHE INTERNAL
    "bfvmm main build dir"
)

set(BUILD_EFI_MAIN_DIR ${CMAKE_BINARY_DIR}/efi_main
    CACHE INTERNAL
    "efi main build dir"
)

# ------------------------------------------------------------------------------
# Includes
# ------------------------------------------------------------------------------

add_config(
    CONFIG_NAME CONFIG
    CONFIG_TYPE STRING
    DEFAULT_VAL ""
    DESCRIPTION "List of additional configs to include in the build"
)

add_config(
    CONFIG_NAME EXTENSION
    CONFIG_TYPE STRING
    DEFAULT_VAL ""
    DESCRIPTION "List of additional extensions to include in the build"
)

# ------------------------------------------------------------------------------
# Configurable directories
# ------------------------------------------------------------------------------

set(DEFAULT_CACHE_DIR ${CMAKE_SOURCE_DIR}/../cache
    CACHE INTERNAL
    "Default cache directory"
)

if(EXISTS ${DEFAULT_CACHE_DIR})
    get_filename_component(DEFAULT_CACHE_DIR "${DEFAULT_CACHE_DIR}" ABSOLUTE)
else()
    set(DEFAULT_CACHE_DIR ${CMAKE_BINARY_DIR}/cache)
endif()

add_config(
    CONFIG_NAME CACHE_DIR
    CONFIG_TYPE PATH
    DEFAULT_VAL ${DEFAULT_CACHE_DIR}
    DESCRIPTION "Cache directory"
    SKIP_VALIDATION
)

# ------------------------------------------------------------------------------
# Non-configurable directories
# ------------------------------------------------------------------------------

set(DEPENDS_DIR ${CMAKE_BINARY_DIR}/depends
    CACHE INTERNAL
    "External dependencies directory"
)

set(PREFIXES_DIR ${CMAKE_BINARY_DIR}/prefixes
    CACHE INTERNAL
    "Prefixes directory"
)

# ------------------------------------------------------------------------------
# Target Properties
# ------------------------------------------------------------------------------

add_config(
    CONFIG_NAME BUILD_TARGET_ARCH
    CONFIG_TYPE STRING
    DEFAULT_VAL ${HOST_SYSTEM_PROCESSOR}
    DESCRIPTION "The target architecture for the build"
    OPTIONS x86_64 aarch64
)

add_config(
    CONFIG_NAME BUILD_TARGET_OS
    CONFIG_TYPE STRING
    DEFAULT_VAL ${HOST_SYSTEM_NAME}
    DESCRIPTION "The target operating system for the build"
    OPTIONS Linux Windows
)

add_config(
    CONFIG_NAME BUILD_TARGET_CORES
    CONFIG_TYPE STRING
    DEFAULT_VAL ${HOST_NUMBER_CORES}
    DESCRIPTION "The target number of cores"
)

# ------------------------------------------------------------------------------
# Config
# ------------------------------------------------------------------------------

set(CMAKE_BUILD_TYPE "Release"
    CACHE INTERNAL
    "Defines the build type"
)

set(CMAKE_VERBOSE_MAKEFILE OFF
    CACHE INTERNAL
    "Enables verbose output"
)

add_config(
    CONFIG_NAME CMAKE_TARGET_MESSAGES
    CONFIG_TYPE BOOL
    DEFAULT_VAL ${CMAKE_VERBOSE_MAKEFILE}
    DESCRIPTION "Enables target messages"
    ADVANCED
)

add_config(
    CONFIG_NAME CMAKE_INSTALL_MESSAGE
    CONFIG_TYPE STRING
    DEFAULT_VAL LAZY
    DESCRIPTION "Defines the install output"
    OPTIONS ALWAYS LAZY NEVER
    ADVANCED
)

# ------------------------------------------------------------------------------
# VMM Library Type
# ------------------------------------------------------------------------------

add_config(
    CONFIG_NAME BUILD_SHARED_LIBS
    CONFIG_TYPE BOOL
    DEFAULT_VAL ON
    DESCRIPTION "Build VMM components as shared libraries"
)

add_config(
    CONFIG_NAME BUILD_STATIC_LIBS
    CONFIG_TYPE BOOL
    DEFAULT_VAL OFF
    DESCRIPTION "Build VMM components as static libraries"
)

# ------------------------------------------------------------------------------
# Prefixes
# ------------------------------------------------------------------------------

add_config(
    CONFIG_NAME VMM_PREFIX
    CONFIG_TYPE PATH
    DEFAULT_VAL ${BUILD_TARGET_ARCH}-vmm-elf
    DESCRIPTION "VMM prefix name"
    SKIP_VALIDATION
    ADVANCED
)

add_config(
    CONFIG_NAME USERSPACE_PREFIX
    CONFIG_TYPE PATH
    DEFAULT_VAL ${BUILD_TARGET_ARCH}-userspace-${HOST_FORMAT_TYPE}
    DESCRIPTION "Userspace prefix name"
    SKIP_VALIDATION
    ADVANCED
)

add_config(
    CONFIG_NAME TEST_PREFIX
    CONFIG_TYPE PATH
    DEFAULT_VAL ${BUILD_TARGET_ARCH}-test-${HOST_FORMAT_TYPE}
    DESCRIPTION "Test prefix name"
    SKIP_VALIDATION
    ADVANCED
)

add_config(
    CONFIG_NAME EFI_PREFIX
    CONFIG_TYPE PATH
    DEFAULT_VAL ${BUILD_TARGET_ARCH}-efi-pe
    DESCRIPTION "EFI prefix name"
    SKIP_VALIDATION
    ADVANCED
)

set(VMM_PREFIX_PATH ${PREFIXES_DIR}/${VMM_PREFIX}
    CACHE INTERNAL
    "VMM prefix path"
)

set(USERSPACE_PREFIX_PATH ${PREFIXES_DIR}/${USERSPACE_PREFIX}
    CACHE INTERNAL
    "Userspace prefix path"
)

set(TEST_PREFIX_PATH ${PREFIXES_DIR}/${TEST_PREFIX}
    CACHE INTERNAL
    "Test prefix path"
)

set(EFI_PREFIX_PATH ${PREFIXES_DIR}/${EFI_PREFIX}
    CACHE INTERNAL
    "EFI prefix path"
)

# ------------------------------------------------------------------------------
# Scripts
# ------------------------------------------------------------------------------

set(TIDY_SCRIPT "${SOURCE_UTIL_DIR}/bareflank_clang_tidy.sh"
    CACHE INTERNAL
    "Clang Tidy script"
)

set(ASTYLE_SCRIPT "${SOURCE_UTIL_DIR}/bareflank_astyle_format.sh"
    CACHE INTERNAL
    "Astyle script"
)

# ------------------------------------------------------------------------------
# Build Switches
# ------------------------------------------------------------------------------

add_config(
    CONFIG_NAME ENABLE_BUILD_VMM
    CONFIG_TYPE BOOL
    DEFAULT_VAL ON
    DESCRIPTION "Build VMM components"
)

add_config(
    CONFIG_NAME ENABLE_BUILD_USERSPACE
    CONFIG_TYPE BOOL
    DEFAULT_VAL ON
    DESCRIPTION "Build userspace components"
)

add_config(
    CONFIG_NAME ENABLE_BUILD_TEST
    CONFIG_TYPE BOOL
    DEFAULT_VAL OFF
    DESCRIPTION "Build unit test components"
)

add_config(
    CONFIG_NAME ENABLE_BUILD_EFI
    CONFIG_TYPE BOOL
    DEFAULT_VAL OFF
    DESCRIPTION "Build efi boot-time loader components"
)

# ------------------------------------------------------------------------------
# EFI Configs
# ------------------------------------------------------------------------------

# add_config(
#     CONFIG_NAME EFI_MODULE_H
#     CONFIG_TYPE STRING
#     DEFAULT_VAL ${EFI_OUTPUT_DIR}/module.h
#     DESCRIPTION "File name of generated module.h for EFI extension adding"
# )

# add_config(
#     CONFIG_NAME EFI_SOURCES_CMAKE
#     CONFIG_TYPE STRING
#     DEFAULT_VAL ${EFI_OUTPUT_DIR}/efi_sources.cmake
#     DESCRIPTION "File name of generated efi_sources.cmake for EFI extension adding"
# )

# ------------------------------------------------------------------------------
# Binutils
# ------------------------------------------------------------------------------

if(NOT DEFINED ENV{LD_BIN})
    set(ENABLE_BUILD_BINUTILS_DEFAULT ON)
else()
    set(ENABLE_BUILD_BINUTILS_DEFAULT OFF)
endif()

add_config(
    CONFIG_NAME ENABLE_BUILD_BINUTILS
    CONFIG_TYPE BOOL
    DEFAULT_VAL ${ENABLE_BUILD_BINUTILS_DEFAULT}
    DESCRIPTION "Build VMM components"
)

# ------------------------------------------------------------------------------
# Developer Features
# ------------------------------------------------------------------------------

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
    DEFAULT_VAL OFF
    DESCRIPTION "Enable clang-tidy"
)

add_config(
    CONFIG_NAME ENABLE_FORMAT
    CONFIG_TYPE BOOL
    DEFAULT_VAL OFF
    DESCRIPTION "Enable astyle formatting"
)

# ------------------------------------------------------------------------------
# Toolchains
# ------------------------------------------------------------------------------

add_config(
    CONFIG_NAME VMM_TOOLCHAIN_PATH
    CONFIG_TYPE FILEPATH
    DEFAULT_VAL ${SOURCE_TOOLCHAIN_DIR}/clang_${BUILD_TARGET_ARCH}_vmm.cmake
    DESCRIPTION "Path to the default cmake toolchain file for building vmm components"
    ADVANCED
)

add_config(
    CONFIG_NAME USERSPACE_TOOLCHAIN_PATH
    CONFIG_TYPE FILEPATH
    DEFAULT_VAL ""
    DESCRIPTION "Path to the default cmake toolchain file for building userspace components"
    SKIP_VALIDATION
    ADVANCED
)

add_config(
    CONFIG_NAME TEST_TOOLCHAIN_PATH
    CONFIG_TYPE FILEPATH
    DEFAULT_VAL ""
    DESCRIPTION "Path to the default cmake toolchain file for building unit tests"
    SKIP_VALIDATION
    ADVANCED
)

add_config(
    CONFIG_NAME EFI_TOOLCHAIN_PATH
    CONFIG_TYPE FILEPATH
    DEFAULT_VAL ${SOURCE_TOOLCHAIN_DIR}/clang_${BUILD_TARGET_ARCH}_efi.cmake
    DESCRIPTION "Path to the default cmake toolchain file for building EFI components"
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

add_config(
    CONFIG_NAME C_FLAGS_TEST
    CONFIG_TYPE STRING
    DEFAULT_VAL ""
    DESCRIPTION "Additional C compiler flags for test components"
)

add_config(
    CONFIG_NAME CXX_FLAGS_TEST
    CONFIG_TYPE STRING
    DEFAULT_VAL ""
    DESCRIPTION "Additional C++ compiler flags for test components"
)

# ------------------------------------------------------------------------------
# Links
# ------------------------------------------------------------------------------

set(GSL_URL "https://github.com/Bareflank/gsl/archive/v2.0.zip"
    CACHE INTERNAL FORCE
    "GSL URL"
)

set(GSL_URL_MD5 "0cc95192658d10e43162ef7b2892e37a"
    CACHE INTERNAL FORCE
    "GSL URL MD5 hash"
)

set(JSON_URL "https://github.com/nlohmann/json/archive/v3.1.2.zip"
    CACHE INTERNAL FORCE
    "JSON URL"
)

set(JSON_URL_MD5 "a5690d84678f50860550633363a44a89"
    CACHE INTERNAL FORCE
    "JSON URL MD5 hash"
)

set(ASTYLE_URL "https://github.com/Bareflank/astyle/archive/v2.0.zip"
    CACHE INTERNAL FORCE
    "Astyle URL"
)

set(ASTYLE_URL_MD5 "4315484ed9b4fbe4dfd534c5db5499a0"
    CACHE INTERNAL FORCE
    "Astyle URL MD5 hash"
)

set(BINUTILS_URL "http://ftp.gnu.org/gnu/binutils/binutils-2.30.tar.gz"
    CACHE INTERNAL FORCE
    "Binutils URL"
)

set(BINUTILS_URL_MD5 "a332503c7f72ad02f4ef624fac34c4af"
    CACHE INTERNAL FORCE
    "Binutils URL MD5 hash"
)

set(NEWLIB_URL "https://github.com/Bareflank/newlib/archive/v2.0.zip"
    CACHE INTERNAL FORCE
    "Newlib URL"
)

set(NEWLIB_URL_MD5 "91588a1a925c953453b2f04acecbcb88"
    CACHE INTERNAL FORCE
    "Newlib URL MD5 hash"
)

set(LLVM_URL "https://github.com/Bareflank/llvm/archive/v2.0.zip"
    CACHE INTERNAL FORCE
    "LLVM URL"
)

set(LLVM_URL_MD5 "7a088762b40665815e47e49dc97ac59f"
    CACHE INTERNAL FORCE
    "LLVM URL MD5 hash"
)

set(LIBCXX_URL "https://github.com/Bareflank/libcxx/archive/v2.0.zip"
    CACHE INTERNAL FORCE
    "Libc++ URL"
)

set(LIBCXX_URL_MD5 "564e6377485bf8527cab085075a626e1"
    CACHE INTERNAL FORCE
    "Libc++ URL MD5 hash"
)

set(LIBCXXABI_URL "https://github.com/Bareflank/libcxxabi/archive/v2.0.zip"
    CACHE INTERNAL FORCE
    "Libc++abi URL"
)

set(LIBCXXABI_URL_MD5 "65dcfe9e14b0076958477953754f9141"
    CACHE INTERNAL FORCE
    "Libc++abi URL MD5 hash"
)

set(CATCH_URL "https://github.com/catchorg/Catch2/archive/v2.2.1.zip"
    CACHE INTERNAL FORCE
    "Catch URL"
)

set(CATCH_URL_MD5 "d1324482a68cdce904a75ae83c74ec73"
    CACHE INTERNAL FORCE
    "Catch URL MD5 hash"
)

set(HIPPOMOCKS_URL "https://github.com/Bareflank/hippomocks/archive/v1.2.zip"
    CACHE INTERNAL FORCE
    "Hippomocks URL"
)

set(HIPPOMOCKS_URL_MD5 "6a0928dfee03fbf4c12c36219c696bae"
    CACHE INTERNAL FORCE
    "Hippomocks URL MD5 hash"
)

set(GNUEFI_URL "https://github.com/Bareflank/gnu-efi/archive/v2.0.zip"
    CACHE INTERNAL FORCE
    "gnu-efi URL")

set(GNUEFI_URL_MD5 "3cd10dc9c14f4a3891f8537fd78ed04f"
    CACHE INTERNAL FORCE
    "gnu-efi URL MD5 hash")

# ------------------------------------------------------------------------------
# BFM Configs
# ------------------------------------------------------------------------------

add_config(
    CONFIG_NAME DEFAULT_VMM
    CONFIG_TYPE STRING
    DEFAULT_VAL bfvmm
    DESCRIPTION "Default vmm"
)

add_config(
    CONFIG_NAME BFM_VMM_BIN_PATH
    CONFIG_TYPE PATH
    DEFAULT_VAL ${VMM_PREFIX_PATH}/bin
    DESCRIPTION "Default path to vmm binaries to be loaded by bfm"
    SKIP_VALIDATION
    ADVANCED
)

add_config(
    CONFIG_NAME BFM_VMM_LIB_PATH
    CONFIG_TYPE PATH
    DEFAULT_VAL ${VMM_PREFIX_PATH}/lib
    DESCRIPTION "Default path to vmm libraries to be loaded by bfm"
    SKIP_VALIDATION
    ADVANCED
)

# ------------------------------------------------------------------------------
# Default Flags
# ------------------------------------------------------------------------------

include(scripts/cmake/flags/asan_flags.cmake)
include(scripts/cmake/flags/codecov_flags.cmake)
include(scripts/cmake/flags/efi_flags.cmake)
include(scripts/cmake/flags/test_flags.cmake)
include(scripts/cmake/flags/usan_flags.cmake)
include(scripts/cmake/flags/userspace_flags.cmake)
include(scripts/cmake/flags/vmm_flags.cmake)
include(scripts/cmake/flags/warning_flags.cmake)
