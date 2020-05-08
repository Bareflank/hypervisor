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

FetchContent_Declare(
    pal
    GIT_REPOSITORY  https://github.com/bareflank/pal.git
    GIT_TAG         adc6d5199a5bdc06c95b9514566872c661cdf831
)

FetchContent_GetProperties(pal)
if(NOT pal_POPULATED)
    set(PAL_QUIET_CMAKE ON)
    set(PAL_TARGET_LANGUAGE c++11)
    set(PAL_OUTPUT_DIR ${CMAKE_BINARY_DIR}/depend/pal-generated-output)

    # TODO: Add a PAL print mechanism for bsl::print. Unil then, turn printing
    # (i.e. dump functions) off in the PAL
    set(PAL_PRINT_MECHANISM none)

    if(${HYPERVISOR_TARGET_ARCH} STREQUAL x86_64)
        set(PAL_TARGET_ARCH intel_x64)
        set(PAL_ACCESS_MECHANISM gas_att)
    elseif(${HYPERVISOR_TARGET_ARCH} STREQUAL AMD64)
        set(PAL_TARGET_ARCH intel_x64)
        set(PAL_ACCESS_MECHANISM gas_att)
    elseif(${HYPERVISOR_TARGET_ARCH} STREQUAL armv8a)
        set(PAL_TARGET_ARCH armv8a)
        set(PAL_ACCESS_MECHANISM gas_aarch64)
    endif()

    FetchContent_Populate(pal)
    add_subdirectory(${pal_SOURCE_DIR} ${pal_BINARY_DIR})
endif()
