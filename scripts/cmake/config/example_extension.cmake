#
# Copyright (C) 2019 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

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
