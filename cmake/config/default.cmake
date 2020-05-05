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

# ------------------------------------------------------------------------------
# options (user configurable)
# ------------------------------------------------------------------------------

option(HYPERVISOR_BUILD_LOADER "Turns on/off building the loader" ON)
option(HYPERVISOR_BUILD_VMMCTL "Turns on/off building the vmmctl" ON)
option(HYPERVISOR_BUILD_MICROV_PLACEHOLDER "Turns on/off building the microv placeholder" ON)

# ------------------------------------------------------------------------------
# settings
# ------------------------------------------------------------------------------

bf_add_config(
    CONFIG_NAME HYPERVISOR_TARGET_ARCH
    CONFIG_TYPE STRING
    DEFAULT_VAL ${CMAKE_HOST_SYSTEM_PROCESSOR}
    DESCRIPTION "The target architecture for the build"
    OPTIONS x86_64 AMD64 armv8a
)

# ------------------------------------------------------------------------------
# validate
# ------------------------------------------------------------------------------

if(NOT CMAKE_SYSTEM_NAME MATCHES "Generic")
    message(FATAL_ERROR "CMAKE_SYSTEM_NAME must be set to Generic: ${CMAKE_SYSTEM_NAME}")
endif()

if(NOT CMAKE_ASM-ATT_COMPILER MATCHES "clang")
    message(FATAL_ERROR "CMAKE_ASM-ATT_COMPILER must be set to a clang compiler")
endif()
