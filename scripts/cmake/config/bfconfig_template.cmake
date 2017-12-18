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

# Use this template and the examples below to configure the Bareflank build
# system and add VMM extensions. Remove the '#' symbol to uncomment a line.
#
# For detailed instructions on configuring and building Bareflank, see
# hypervisor/scripts/docs/build_instructions.md.

# For detailed instructions on configuring and adding VMM extensions, see
# hypervisor/scripts/docs/extension_instructions.md

# To view all available build system configuration variables, use ccmake or
# cmake-gui from your build directory:
#      cd </path/to>/build; ccmake .

# ------------------------------------------------------------------------------
# Bareflank Build Configurations
# ------------------------------------------------------------------------------

# set(BUILD_TYPE Debug)
# set(BUILD_VMM_STATIC ON)
# set(ENABLE_DEVELOPER_MODE ON)

# ------------------------------------------------------------------------------
# Bareflank Extensions
# ------------------------------------------------------------------------------

# vmm_extension(
#     extended_apis
#     GIT_REPOSITORY https://github.com/bareflank/extended_apis.git
#     GIT_TAG dev
# )

# vmm_extension(
#     my_extension
#     SOURCE_DIR ~/bareflank/my_extension
#     DEPENDS extended_apis
# )
