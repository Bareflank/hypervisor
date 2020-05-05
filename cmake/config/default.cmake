#
# Copyright (C) 2020 Assured Information Security, Inc.
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

include(${bsl_SOURCE_DIR}/cmake/function/bf_add_config.cmake)

option(HYPERVISOR_BUILD_LOADER "Turns on/off building the loader" ON)
option(HYPERVISOR_BUILD_VMMCTL "Turns on/off building the vmmctl" ON)
option(HYPERVISOR_BUILD_EXAMPLES_OVERRIDE "Prevents the examples from being built when enabled" OFF)
option(HYPERVISOR_BUILD_TESTS_OVERRIDE "Prevents the tests from being built when enabled" OFF)
option(HYPERVISOR_INCLUDE_INFO_OVERRIDE "Prevents the hypervisor from creating an info target when enabled" OFF)

bf_add_config(
    CONFIG_NAME HYPERVISOR_TARGET_ARCH
    CONFIG_TYPE STRING
    DEFAULT_VAL ${CMAKE_HOST_SYSTEM_PROCESSOR}
    DESCRIPTION "The target architecture for the build"
    OPTIONS x86_64 AMD64 armv8a
)
