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

# This file gets included by all Bareflank extensions to set up some cmake
# boilerplate, and to set up default Bareflank conventions. The top level
# CMakeLists.txt for all Bareflank extensions should include this file using:
#
# include(${BF_VMM_EXTENSION})
#

# ------------------------------------------------------------------------------
# Setup VMM extension cmake environment
# ------------------------------------------------------------------------------

include(${BF_SCRIPTS_DIR}/cmake/macros.cmake)
include(${BF_SCRIPTS_DIR}/cmake/macros_extension.cmake)
include(${BF_SCRIPTS_DIR}/cmake/config/default_extension.cmake)
if(EXISTS ${VMM_EX_CONFIGS})
    include(${VMM_EX_CONFIGS})
endif()
include(${BF_FLAGS_DIR}/flags.cmake)

if(VMM_EX_IS_UNITTEST_BUILD)
    include(CTest)
    enable_testing(true)
    generate_flags(
        USERSPACE
        ADD_C_FLAGS
            "-fvisibility=hidden"
            "-DDEBUG_LEVEL=1"
            "-DENABLE_UNITTESTING"
        ADD_CXX_FLAGS
            "-fvisibility=hidden"
            "-fvisibility-inlines-hidden"
            "-DDEBUG_LEVEL=1"
            "-DENABLE_UNITTESTING"
        VERBOSE ${BUILD_VERBOSE}
    )

    include_directories(
        ${VMM_EX_INCLUDE_DIR}
        ${BUILD_SYSROOT_OS}/include
        ${BUILD_SYSROOT_TEST}/include
    )

    link_directories(
        ${BUILD_SYSROOT_OS}/lib
        ${BUILD_SYSROOT_TEST}/lib
    )
else()
    generate_flags(VMM)

    include_directories(
        ${VMM_EX_INCLUDE_DIR}
        ${VMM_EX_SYSROOT}/include/c++/v1
        ${VMM_EX_SYSROOT}/include
    )

    link_directories(${BUILD_SYSROOT_VMM}/lib)
endif()

# Force a dummy "install" target if this extension doesn't install any files
install(CODE "")

# ------------------------------------------------------------------------------
# VMM extension build system conventions
# ------------------------------------------------------------------------------

if(EXISTS ${VMM_EX_BUILD_RULES})
    include(${VMM_EX_BUILD_RULES})
    validate_build()
endif()

if(EXISTS ${VMM_EX_SOURCE_DIR}/CMakeLists.txt)
    add_subdirectory(${VMM_EX_SOURCE_DIR})
endif()

if(VMM_EX_IS_UNITTEST_BUILD AND EXISTS ${VMM_EX_UNITTEST_DIR}/CMakeLists.txt)
    add_subdirectory(${VMM_EX_UNITTEST_DIR})
endif()
