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

# For a complete example of how to use a VMM extension, please see the
# following example:
# https://github.com/Bareflank/hypervisor_example_cpuidcount

# ------------------------------------------------------------------------------
# Extension
# ------------------------------------------------------------------------------

# Add Subproject
#
# To add an extension, use the add_subproject macro. This macro tells the build
# system to include an external project. This is the same macro used by the
# main build system. Like the main build system, the extension must contain
# it's own sub project.
#
#add_subproject(
#    <name> vmm
#    DEPENDS bfvmm bfintrinsics <dependencies>
#    SOURCE_DIR <path>
#)

# Subproject Layout
#
# Like all subprojects, your project must start with cmake's project macro.
# In addition, the init_project macro must be used which ensures the projects
# variables are properly setup based on the prefix you intend to use (which
# will likely be the "vmm"). Finally, you can use the add_xxx_library
# functions or you can use the add_vmm_executable function as shown in
# this example.
#
#cmake_minimum_required(VERSION 3.6)
#project(example_vmm C CXX)
#
#include(${SOURCE_CMAKE_DIR}/project.cmake)
#init_project()
#
#add_vmm_executable(example_vmm
#    SOURCES <filename>.cpp
#)
