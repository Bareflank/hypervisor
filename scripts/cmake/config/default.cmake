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

execute_process(COMMAND uname -o OUTPUT_VARIABLE UNAME OUTPUT_STRIP_TRAILING_WHITESPACE)
if(UNAME STREQUAL "Cygwin" OR WIN32)
    set(OSTYPE "WIN64" CACHE INTERNAL "")
    set(ABITYPE "MS64" CACHE INTERNAL "")
else()
    set(OSTYPE "UNIX" CACHE INTERNAL "")
    set(ABITYPE "SYSV" CACHE INTERNAL "")
endif()

if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
    set(HOST_FORMAT_TYPE "pe" CACHE INTERNAL "")
    set(HOST_SYSTEM_NAME "Windows" CACHE INTERNAL "")
elseif(CMAKE_HOST_SYSTEM_NAME STREQUAL "CYGWIN")
    set(HOST_FORMAT_TYPE "pe" CACHE INTERNAL "")
    set(HOST_SYSTEM_NAME "Windows" CACHE INTERNAL "")
else()
    set(HOST_FORMAT_TYPE "elf" CACHE INTERNAL "")
    set(HOST_SYSTEM_NAME "Linux" CACHE INTERNAL "")
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
# Source tree structure
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
# Build tree structure
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

# ------------------------------------------------------------------------------
# Configurable directories
# ------------------------------------------------------------------------------

set(DEFAULT_CACHE_DIR ${CMAKE_SOURCE_DIR}/../cache
    CACHE INTERNAL
    "Default cache directory"
)

set(DEFAULT_DEPENDS_DIR ${CMAKE_SOURCE_DIR}/../depends
    CACHE INTERNAL
    "Default external dependencies directory"
)

set(DEFAULT_PREFIXES_DIR ${CMAKE_SOURCE_DIR}/../prefixes
    CACHE INTERNAL
    "Default prefixes directory"
)

if(EXISTS ${DEFAULT_CACHE_DIR})
    get_filename_component(DEFAULT_CACHE_DIR "${DEFAULT_CACHE_DIR}" ABSOLUTE)
else()
    set(DEFAULT_CACHE_DIR ${CMAKE_BINARY_DIR}/cache)
endif()

if(EXISTS ${DEFAULT_DEPENDS_DIR})
    get_filename_component(DEFAULT_DEPENDS_DIR "${DEFAULT_DEPENDS_DIR}" ABSOLUTE)
else()
    set(DEFAULT_DEPENDS_DIR ${CMAKE_BINARY_DIR}/depends)
endif()

if(EXISTS ${DEFAULT_PREFIXES_DIR})
    get_filename_component(DEFAULT_PREFIXES_DIR "${DEFAULT_PREFIXES_DIR}" ABSOLUTE)
else()
    set(DEFAULT_PREFIXES_DIR ${CMAKE_BINARY_DIR}/prefixes)
endif()

add_config(
    CONFIG_NAME CACHE_DIR
    CONFIG_TYPE PATH
    DEFAULT_VAL ${DEFAULT_CACHE_DIR}
    DESCRIPTION "Cache directory"
    SKIP_VALIDATION
)

add_config(
    CONFIG_NAME DEPENDS_DIR
    CONFIG_TYPE PATH
    DEFAULT_VAL ${DEFAULT_DEPENDS_DIR}
    DESCRIPTION "External dependencies directory"
    SKIP_VALIDATION
)

add_config(
    CONFIG_NAME PREFIXES_DIR
    CONFIG_TYPE PATH
    DEFAULT_VAL ${DEFAULT_PREFIXES_DIR}
    DESCRIPTION "Prefixes directory"
    SKIP_VALIDATION
)

# ------------------------------------------------------------------------------
# Build attributes
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

add_config(
    CONFIG_NAME CMAKE_TARGET_MESSAGES
    CONFIG_TYPE BOOL
    DEFAULT_VAL OFF
    DESCRIPTION "Enables target messages"
)

add_config(
    CONFIG_NAME CMAKE_INSTALL_MESSAGE
    CONFIG_TYPE STRING
    DEFAULT_VAL LAZY
    DESCRIPTION "Defines the install output"
    OPTIONS ALWAYS LAZY NEVER
)

add_config(
    CONFIG_NAME CMAKE_BUILD_TYPE
    CONFIG_TYPE STRING
    DEFAULT_VAL Release
    DESCRIPTION "Defines the build type"
    Release Debug
)

add_config(
    CONFIG_NAME CMAKE_VERBOSE_MAKEFILE
    CONFIG_TYPE BOOL
    DEFAULT_VAL OFF
    DESCRIPTION "Enables verbose output"
)

# ------------------------------------------------------------------------------
# VMM build type
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
# Sysroots
# ------------------------------------------------------------------------------

add_config(
    CONFIG_NAME VMM_PREFIX
    CONFIG_TYPE PATH
    DEFAULT_VAL ${BUILD_TARGET_ARCH}-vmm-elf
    DESCRIPTION "VMM prefix name"
    SKIP_VALIDATION
)

add_config(
    CONFIG_NAME USERSPACE_PREFIX
    CONFIG_TYPE PATH
    DEFAULT_VAL ${BUILD_TARGET_ARCH}-userspace-${HOST_FORMAT_TYPE}
    DESCRIPTION "Userspace prefix name"
    SKIP_VALIDATION
)

add_config(
    CONFIG_NAME TEST_PREFIX
    CONFIG_TYPE PATH
    DEFAULT_VAL ${BUILD_TARGET_ARCH}-test-${HOST_FORMAT_TYPE}
    DESCRIPTION "Test prefix name"
    SKIP_VALIDATION
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

# ------------------------------------------------------------------------------
# Scripts
# ------------------------------------------------------------------------------

set(ASTYLE_SCRIPT "${SOURCE_UTIL_DIR}/bareflank_astyle_format.sh"
    CACHE INTERNAL
    "Astyle script"
)

set(TIDY_SCRIPT "${SOURCE_UTIL_DIR}/bareflank_clang_tidy.sh"
    CACHE INTERNAL
    "Clang Tidy script"
)

# ------------------------------------------------------------------------------
# Build switches
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
# Tidy Exclusions
# ------------------------------------------------------------------------------

add_config(
    CONFIG_NAME TIDY_EXCLUSION_DRIVER
    CONFIG_TYPE STRING
    DEFAULT_VAL ""
    DESCRIPTION "Cland Tidy exclusions for bfdriver"
)

add_config(
    CONFIG_NAME TIDY_EXCLUSION_BFDUMMY
    CONFIG_TYPE STRING
    DEFAULT_VAL ""
    DESCRIPTION "Cland Tidy exclusions for bfdummy"
)

add_config(
    CONFIG_NAME TIDY_EXCLUSION_BFELF_LOADER
    CONFIG_TYPE STRING
    DEFAULT_VAL ",-cppcoreguidelines-pro-type-const-cast"
    DESCRIPTION "Cland Tidy exclusions for bfelf_loader"
)

add_config(
    CONFIG_NAME TIDY_EXCLUSION_BFINTRINSICS
    CONFIG_TYPE STRING
    DEFAULT_VAL ""
    DESCRIPTION "Cland Tidy exclusions for bfintrinsics"
)

add_config(
    CONFIG_NAME TIDY_EXCLUSION_BFM
    CONFIG_TYPE STRING
    DEFAULT_VAL ""
    DESCRIPTION "Cland Tidy exclusions for bfm"
)

add_config(
    CONFIG_NAME TIDY_EXCLUSION_BFRUNTIME
    CONFIG_TYPE STRING
    DEFAULT_VAL ",-cppcoreguidelines-pro*,-cert-err34-c,-misc-misplaced-widening-cast"
    DESCRIPTION "Cland Tidy exclusions for bfruntime"
)

add_config(
    CONFIG_NAME TIDY_EXCLUSION_BFSDK
    CONFIG_TYPE STRING
    DEFAULT_VAL ""
    DESCRIPTION "Cland Tidy exclusions for bfsdk"
)

add_config(
    CONFIG_NAME TIDY_EXCLUSION_BFUNWIND
    CONFIG_TYPE STRING
    DEFAULT_VAL ""
    DESCRIPTION "Cland Tidy exclusions for bfunwind"
)

add_config(
    CONFIG_NAME TIDY_EXCLUSION_BFVMM
    CONFIG_TYPE STRING
    DEFAULT_VAL ""
    DESCRIPTION "Cland Tidy exclusions for bfvmm"
)

# ------------------------------------------------------------------------------
# High-level cmake toolchains
# ------------------------------------------------------------------------------

add_config(
    CONFIG_NAME VMM_TOOLCHAIN_PATH
    CONFIG_TYPE FILEPATH
    DEFAULT_VAL ${SOURCE_TOOLCHAIN_DIR}/clang_${BUILD_TARGET_ARCH}_vmm.cmake
    DESCRIPTION "Path to the default cmake toolchain file for building vmm components"
)

add_config(
    CONFIG_NAME VMM_TEST_TOOLCHAIN_PATH
    CONFIG_TYPE FILEPATH
    DEFAULT_VAL ${SOURCE_TOOLCHAIN_DIR}/clang_${BUILD_TARGET_ARCH}_vmm_test.cmake
    DESCRIPTION "Path to the default cmake toolchain file for building vmm components for testing"
)

add_config(
    CONFIG_NAME USERSPACE_TOOLCHAIN_PATH
    CONFIG_TYPE FILEPATH
    DEFAULT_VAL ""
    DESCRIPTION "Path to the default cmake toolchain file for building userspace components"
    SKIP_VALIDATION
)

add_config(
    CONFIG_NAME TEST_TOOLCHAIN_PATH
    CONFIG_TYPE FILEPATH
    DEFAULT_VAL ""
    DESCRIPTION "Path to the default cmake toolchain file for building unit tests"
    SKIP_VALIDATION
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

add_config(
    CONFIG_NAME GSL_URL
    CONFIG_TYPE STRING
    DEFAULT_VAL "https://github.com/Bareflank/gsl/archive/v1.2.zip"
    DESCRIPTION "GSL URL"
)

add_config(
    CONFIG_NAME GSL_URL_MD5
    CONFIG_TYPE STRING
    DEFAULT_VAL "629de6bd0ee501223919cf395fb6ffed"
    DESCRIPTION "GSL URL MD5 hash"
)

add_config(
    CONFIG_NAME JSON_URL
    CONFIG_TYPE STRING
    DEFAULT_VAL "https://github.com/Bareflank/json/archive/v1.2.zip"
    DESCRIPTION "JSON URL"
)

add_config(
    CONFIG_NAME JSON_URL_MD5
    CONFIG_TYPE STRING
    DEFAULT_VAL "7d61cb7accecdbc0fa32d89a52a32153"
    DESCRIPTION "JSON URL MD5 hash"
)

add_config(
    CONFIG_NAME ASTYLE_URL
    CONFIG_TYPE STRING
    DEFAULT_VAL "https://github.com/Bareflank/astyle/archive/v1.2.zip"
    DESCRIPTION "Astyle URL"
)

add_config(
    CONFIG_NAME ASTYLE_URL_MD5
    CONFIG_TYPE STRING
    DEFAULT_VAL "339d6ce8d4f34a3737e1c44b95c3b4dd"
    DESCRIPTION "Astyle URL MD5 hash"
)

add_config(
    CONFIG_NAME BINUTILS_URL
    CONFIG_TYPE STRING
    DEFAULT_VAL "http://ftp.gnu.org/gnu/binutils/binutils-2.28.tar.gz"
    DESCRIPTION "Binutils URL"
)

add_config(
    CONFIG_NAME BINUTILS_URL_MD5
    CONFIG_TYPE STRING
    DEFAULT_VAL "d5d270fd0b698ed59ca5ade8e1b5059c"
    DESCRIPTION "Binutils URL MD5 hash"
)

add_config(
    CONFIG_NAME NEWLIB_URL
    CONFIG_TYPE STRING
    DEFAULT_VAL "https://github.com/Bareflank/newlib/archive/v1.2.zip"
    DESCRIPTION "Newlib URL"
)

add_config(
    CONFIG_NAME NEWLIB_URL_MD5
    CONFIG_TYPE STRING
    DEFAULT_VAL "6a634f488170ab2204db899407cc2d6d"
    DESCRIPTION "Newlib URL MD5 hash"
)

add_config(
    CONFIG_NAME LLVM_URL
    CONFIG_TYPE STRING
    DEFAULT_VAL "https://github.com/Bareflank/llvm/archive/v1.2.zip"
    DESCRIPTION "LLVM URL"
)

add_config(
    CONFIG_NAME LLVM_URL_MD5
    CONFIG_TYPE STRING
    DEFAULT_VAL "561bfc6a4cefbf287a2e9ca6815c7ee0"
    DESCRIPTION "LLVM URL MD5 hash"
)

add_config(
    CONFIG_NAME LIBCXX_URL
    CONFIG_TYPE STRING
    DEFAULT_VAL "https://github.com/Bareflank/libcxx/archive/v1.2.zip"
    DESCRIPTION "Libc++ URL"
)

add_config(
    CONFIG_NAME LIBCXX_URL_MD5
    CONFIG_TYPE STRING
    DEFAULT_VAL "562ea68e9f483ab7ca62b21fdbf0ee89"
    DESCRIPTION "Libc++ URL MD5 hash"
)

add_config(
    CONFIG_NAME LIBCXXABI_URL
    CONFIG_TYPE STRING
    DEFAULT_VAL "https://github.com/Bareflank/libcxxabi/archive/v1.2.zip"
    DESCRIPTION "Libc++abi URL"
)

add_config(
    CONFIG_NAME LIBCXXABI_URL_MD5
    CONFIG_TYPE STRING
    DEFAULT_VAL "a118c53b17110f23dcb567f2b8c73d9a"
    DESCRIPTION "Libc++abi URL MD5 hash"
)

add_config(
    CONFIG_NAME CATCH_URL
    CONFIG_TYPE STRING
    DEFAULT_VAL "https://github.com/Bareflank/catch/archive/v1.2.zip"
    DESCRIPTION "Catch URL"
)

add_config(
    CONFIG_NAME CATCH_URL_MD5
    CONFIG_TYPE STRING
    DEFAULT_VAL "ed2f6eec62fc8e825e622deedf50f6b4"
    DESCRIPTION "Catch URL MD5 hash"
)

add_config(
    CONFIG_NAME HIPPOMOCKS_URL
    CONFIG_TYPE STRING
    DEFAULT_VAL "https://github.com/Bareflank/hippomocks/archive/v1.2.zip"
    DESCRIPTION "Hippomocks URL"
)

add_config(
    CONFIG_NAME HIPPOMOCKS_URL_MD5
    CONFIG_TYPE STRING
    DEFAULT_VAL "6a0928dfee03fbf4c12c36219c696bae"
    DESCRIPTION "Hippomocks URL MD5 hash"
)

# ------------------------------------------------------------------------------
# BFM Configs
# ------------------------------------------------------------------------------

add_config(
    CONFIG_NAME BFM_VMM_BIN_PATH
    CONFIG_TYPE PATH
    DEFAULT_VAL ${VMM_PREFIX_PATH}/bin
    DESCRIPTION "Default path to vmm binaries to be loaded by bfm"
    SKIP_VALIDATION
)

add_config(
    CONFIG_NAME BFM_VMM_LIB_PATH
    CONFIG_TYPE PATH
    DEFAULT_VAL ${VMM_PREFIX_PATH}/lib
    DESCRIPTION "Default path to vmm libraries to be loaded by bfm"
    SKIP_VALIDATION
)

set_bfm_vmm(bfvmm DEFAULT)

# ------------------------------------------------------------------------------
# Default Flags
# ------------------------------------------------------------------------------

include(scripts/cmake/flags/asan_flags.cmake)
include(scripts/cmake/flags/codecov_flags.cmake)
include(scripts/cmake/flags/test_flags.cmake)
include(scripts/cmake/flags/usan_flags.cmake)
include(scripts/cmake/flags/userspace_flags.cmake)
include(scripts/cmake/flags/vmm_flags.cmake)
include(scripts/cmake/flags/warning_flags.cmake)
