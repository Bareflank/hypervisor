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

include(${bsl_SOURCE_DIR}/cmake/function/bf_add_test.cmake)

# ------------------------------------------------------------------------------
# Includes
# ------------------------------------------------------------------------------

list(APPEND INCLUDES
    ${CMAKE_CURRENT_LIST_DIR}/.
)

list(APPEND SYSTEM_INCLUDES
    ${CMAKE_CURRENT_LIST_DIR}/../../loader/include/interface/cpp
)

# ------------------------------------------------------------------------------
# Definitions
# ------------------------------------------------------------------------------

list(APPEND DEFINES
    HYPERVISOR_DEBUG_RING_SIZE=0x7FF0
)

# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------

add_subdirectory(main)
add_subdirectory(vmmctl_main)

add_subdirectory(linux/ifmap)
add_subdirectory(linux/ioctl)

add_subdirectory(windows/ifmap)
add_subdirectory(windows/ioctl)
