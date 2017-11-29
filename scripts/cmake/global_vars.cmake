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

# This file defines all NON CONFIGURABLE cmake variables that are shared across
# all sub-projects. The "BF_" prefix signifies that the variable is bareflank
# specific and applies to all sub-projects and dependencies globally
#
# Do NOT assign built-in CMake variables here (vars that start with "CMAKE_")
#

# ------------------------------------------------------------------------------
# Source tree structure
# ------------------------------------------------------------------------------

set(BF_SOURCE_DIR ${CMAKE_SOURCE_DIR}
    CACHE INTERNAL
    "Top-level source directory"
)

set(BF_SCRIPTS_DIR "${BF_SOURCE_DIR}/scripts"
    CACHE INTERNAL
    "Scripts directory"
)

set(BF_CONFIG_DIR "${BF_SCRIPTS_DIR}/cmake/config"
    CACHE INTERNAL
    "Cmake build configurations directory"
)

set(BF_DEPENDS_DIR "${BF_SCRIPTS_DIR}/cmake/depends"
    CACHE INTERNAL
    "Cmake external dependencies directory"
)

set(BF_FLAGS_DIR "${BF_SCRIPTS_DIR}/cmake/flags"
    CACHE INTERNAL
    "Cmake compiler flags directory"
)

set(BF_TOOLCHAIN_DIR "${BF_SCRIPTS_DIR}/cmake/toolchain"
    CACHE INTERNAL
    "Cmake toolchain files directory"
)

# ------------------------------------------------------------------------------
# Build tree structure
# ------------------------------------------------------------------------------

set(BF_BUILD_DIR ${CMAKE_BINARY_DIR}
    CACHE INTERNAL
    "Top-level build directory"
)

set(BF_BUILD_DEPENDS_DIR ${BF_BUILD_DIR}/depends
    CACHE INTERNAL
    "Build directory for external dependencies"
)

set(BF_BUILD_INSTALL_DIR "${BF_BUILD_DIR}/install"
    CACHE INTERNAL
    "Intermediate build installation directory"
)

set(BF_BUILD_DIR_BFDRIVER "${BF_BUILD_DIR}/bfdriver/build"
    CACHE INTERNAL
    "Build directory for bfdriver"
)

set(BF_BUILD_DIR_BFDRIVER_TEST "${BF_BUILD_DIR}/bfdriver_test/build"
    CACHE INTERNAL
    "Build directory for bfdriver unit tests"
)

set(BF_BUILD_DIR_BFELF_LOADER "${BF_BUILD_DIR}/bfelf_loader/build"
    CACHE INTERNAL
    "Build directory for bfelf_loader"
)

set(BF_BUILD_DIR_BFELF_LOADER_TEST "${BF_BUILD_DIR}/bfelf_loader_test/build"
    CACHE INTERNAL
    "Build directory for bfelf_loader unit tests"
)

set(BF_BUILD_DIR_BFM "${BF_BUILD_DIR}/bfm/build"
    CACHE INTERNAL
    "Build directory for bfm"
)

set(BF_BUILD_DIR_BFM_TEST "${BF_BUILD_DIR}/bfm_test/build"
    CACHE INTERNAL
    "Build directory for bfm unit tests"
)

set(BF_BUILD_DIR_BFSDK "${BF_BUILD_DIR}/bfsdk/build"
    CACHE INTERNAL
    "Build directory for bfsdk"
)

set(BF_BUILD_DIR_BFSDK_TEST "${BF_BUILD_DIR}/bfsdk_test/build"
    CACHE INTERNAL
    "Build directory for bfsdk unit tests"
)

set(BF_BUILD_DIR_BFSUPPORT "${BF_BUILD_DIR}/bfsupport/build"
    CACHE INTERNAL
    "Build directory for bfsupport unit tests"
)

set(BF_BUILD_DIR_BFSUPPORT_TEST "${BF_BUILD_DIR}/bfsupport_test/build"
    CACHE INTERNAL
    "Build directory for bfsupport unit tests"
)

set(BF_BUILD_DIR_BFUNWIND "${BF_BUILD_DIR}/bfunwind/build"
    CACHE INTERNAL
    "Build directory for bfunwind"
)

set(BF_BUILD_DIR_BFVMM "${BF_BUILD_DIR}/bfvmm/build"
    CACHE INTERNAL
    "Build directory for bfvmm"
)

set(BF_BUILD_DIR_BFVMM_TEST "${BF_BUILD_DIR}/bfvmm_test/build"
    CACHE INTERNAL
    "Build directory for bfvmm tests"
)

set(BF_BUILD_DIR_EXTENDED_APIS "${BF_BUILD_DIR}/extended_apis/build"
    CACHE INTERNAL
    "Build directory for bareflank Extended APIs"
)

set(BF_BUILD_DIR_EXTENDED_APIS_TEST "${BF_BUILD_DIR}/extended_apis_test/build"
    CACHE INTERNAL
    "Build directory for bareflank Extended APIs unit tests"
)

# ------------------------------------------------------------------------------
# Console text color palette
# ------------------------------------------------------------------------------

if(NOT WIN32)
    string(ASCII 27 Esc)
    set(ColorReset "${Esc}[m")
    set(ColorBold  "${Esc}[1m")
    set(Red         "${Esc}[31m")
    set(Green       "${Esc}[32m")
    set(Yellow      "${Esc}[33m")
    set(Blue        "${Esc}[34m")
    set(Magenta     "${Esc}[35m")
    set(Cyan        "${Esc}[36m")
    set(White       "${Esc}[37m")
    set(BoldRed     "${Esc}[1;31m")
    set(BoldGreen   "${Esc}[1;32m")
    set(BoldYellow  "${Esc}[1;33m")
    set(BoldBlue    "${Esc}[1;34m")
    set(BoldMagenta "${Esc}[1;35m")
    set(BoldCyan    "${Esc}[1;36m")
    set(BoldWhite   "${Esc}[1;37m")
else()
    set(ColorReset "")
    set(ColorBold  "")
    set(Red         "")
    set(Green       "")
    set(Yellow      "")
    set(Blue        "")
    set(Magenta     "")
    set(Cyan        "")
    set(White       "")
    set(BoldRed     "")
    set(BoldGreen   "")
    set(BoldYellow  "")
    set(BoldBlue    "")
    set(BoldMagenta "")
    set(BoldCyan    "")
    set(BoldWhite   "")
endif()

# ------------------------------------------------------------------------------
# Miscellaneous
# ------------------------------------------------------------------------------

STRING(FIND ${CMAKE_GENERATOR} "Makefile" is_make)
STRING(FIND ${CMAKE_GENERATOR} "Ninja" is_ninja)
STRING(FIND ${CMAKE_GENERATOR} "Visual Studio" is_vs)
set(BF_BUILD_COMMAND ""
    CACHE INTERNAL
    "The name of the command-line tool to be used to build generated Cmake output (i.e. make, ninja, msbuild, etc)"
)
if(NOT is_make EQUAL -1)
    set(BF_BUILD_COMMAND "make")
elseif(NOT is_ninja EQUAL -1)
    set(BF_BUILD_COMMAND "ninja")
elseif(NOT is_vs EQUAL -1)
    set(BF_BUILD_COMMAND "msbuild")
else()
    message(FATAL_ERROR "Unsupported cmake generator: ${CMAKE_GENERATOR}")
endif()

if(NOT WIN32 AND NOT CYGWIN)
    set(SUDO sudo)
else()
    set(SUDO "")
endif()
