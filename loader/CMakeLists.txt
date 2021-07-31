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

add_library(loader INTERFACE)

# ------------------------------------------------------------------------------
# Includes
# ------------------------------------------------------------------------------

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    target_include_directories(loader SYSTEM INTERFACE
        ${CMAKE_CURRENT_LIST_DIR}/include/interface/x64
    )
endif()

if(HYPERVISOR_TARGET_ARCH STREQUAL "aarch64")
    target_include_directories(loader SYSTEM INTERFACE
        ${CMAKE_CURRENT_LIST_DIR}/include/interface/arm/aarch64
    )
endif()

target_include_directories(loader SYSTEM INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}/include/interface

    $<$<PLATFORM_ID:Linux>:${CMAKE_CURRENT_LIST_DIR}/linux/include>
    $<$<PLATFORM_ID:Linux>:${CMAKE_CURRENT_LIST_DIR}/linux/include/platform_interface>
    $<$<PLATFORM_ID:Windows>:${CMAKE_CURRENT_LIST_DIR}/windows/include>
    $<$<PLATFORM_ID:Windows>:${CMAKE_CURRENT_LIST_DIR}/windows/include/platform_interface>
)

# ------------------------------------------------------------------------------
# Sub Directories
# ------------------------------------------------------------------------------

if(HYPERVISOR_BUILD_EFI)
    hypervisor_add_efi_cross_compile(../cmake/efi_cross_compile)
endif()
