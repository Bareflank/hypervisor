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

# This file defines all configurable cmake variables available to Barefank
# VMM extensions, set to their default value. These configuration are NOT
# available to base Bareflank hypervisor projects. VMM extension projects
# can use both these configurations PLUS the base hypervisor configurations.

# Each configuration here indicates the Bareflank suggested convention as
# a default value. The goal is to encourage a "convention over configuration"
# mindset for extension developers. If extension developers choose not follow
# a suggested convention, they can override a configuration using two methods:
#
# 1) Specify each configuration as CMAKE_ARGS to the vmm_extension() macro. Ex:
#
#     vmm_extension(
#           extension_name
#           CMAKE_ARGS -DVMM_EX_BUILD_RULES=/path/to/build_rules.cmake
#     )
#
# 2) Override a configuration in the extension's CMakeLists.txt file BEFORE
#    calling include(${VMM_EXTENSION}). Ex:
#
#     set(VMM_EX_BUILD_RULES "/path/to/build_rules.cmake")
#     set(VMM_EX_UNITTEST_PATH "/path/to/the/unit/tests")
#     include(${VMM_EXTENSION})
#

# ------------------------------------------------------------------------------
# Source tree structure
# ------------------------------------------------------------------------------

add_config(
    CONFIG_NAME VMM_EX_TOP_DIR
    CONFIG_TYPE PATH
    DEFAULT_VAL ${CMAKE_CURRENT_SOURCE_DIR}
    DESCRIPTION "Path to the top directory for this VMM extension"
)

add_config(
    CONFIG_NAME VMM_EX_SOURCE_DIR
    CONFIG_TYPE PATH
    DEFAULT_VAL ${VMM_EX_TOP_DIR}/src
    DESCRIPTION "Path to the source code directory for this VMM extension"
    SKIP_VALIDATION
)

add_config(
    CONFIG_NAME VMM_EX_INCLUDE_DIR
    CONFIG_TYPE PATH
    DEFAULT_VAL ${VMM_EX_TOP_DIR}/include
    DESCRIPTION "Path to the header include directory for this VMM extension"
    SKIP_VALIDATION
)

add_config(
    CONFIG_NAME VMM_EX_UNITTEST_DIR
    CONFIG_TYPE PATH
    DEFAULT_VAL ${VMM_EX_TOP_DIR}/test
    DESCRIPTION "Path to the unit test directory for this VMM extension"
    SKIP_VALIDATION
)

# ------------------------------------------------------------------------------
# Build system features
# ------------------------------------------------------------------------------

add_config(
    CONFIG_NAME VMM_EX_CONFIGS
    CONFIG_TYPE FILE
    DEFAULT_VAL ${VMM_EX_TOP_DIR}/configs.cmake
    DESCRIPTION "Path to extention-specific build configurations to be added "
                "for this VMM extension"
    SKIP_VALIDATION
)

add_config(
    CONFIG_NAME VMM_EX_BUILD_RULES
    CONFIG_TYPE FILE
    DEFAULT_VAL ${VMM_EX_TOP_DIR}/build_rules.cmake
    DESCRIPTION "Path to a build rules file to be validated before building "
                "this VMM extension"
    SKIP_VALIDATION
)

# ------------------------------------------------------------------------------
# Read-only variables
# ------------------------------------------------------------------------------

add_config(
    CONFIG_NAME VMM_EX_IS_UNITTEST_BUILD
    CONFIG_TYPE INTERNAL
    DEFAULT_VAL OFF
    DESCRIPTION "The build system sets this variable to ON if this extension's "
    "unit tests are currently being built, rather than it's source"
    SKIP_VALIDATION
)

if(VMM_EX_IS_UNTTEST_BUILD)
    set(_VMM_EX_SYSROOT_DEFAULT ${BUILD_SYSROOT_TEST})
else()
    set(_VMM_EX_SYSROOT_DEFAULT ${BUILD_SYSROOT_VMM})
endif()
add_config(
    CONFIG_NAME VMM_EX_SYSROOT
    CONFIG_TYPE INTERNAL
    DEFAULT_VAL ${_VMM_EX_SYSROOT_DEFAULT}
    DESCRIPTION "Path to this VMM extension's sysroot"
    SKIP_VALIDATION
)
