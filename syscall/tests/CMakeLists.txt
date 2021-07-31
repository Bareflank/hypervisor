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
    ${CMAKE_CURRENT_LIST_DIR}/../include
    ${CMAKE_CURRENT_LIST_DIR}/../mocks
    ${CMAKE_CURRENT_LIST_DIR}/../../lib/include
)

# ------------------------------------------------------------------------------
# Definitions
# ------------------------------------------------------------------------------

list(APPEND DEFINES
    HYPERVISOR_MAX_PPS=10_umx
    HYPERVISOR_MAX_VMS=10_umx
    HYPERVISOR_MAX_VPS=10_umx
    HYPERVISOR_MAX_VSS=10_umx
    HYPERVISOR_PAGE_SIZE=0x1000_umx
    HYPERVISOR_EXT_DIRECT_MAP_ADDR=0x1000_umx
    HYPERVISOR_EXT_DIRECT_MAP_SIZE=0x0000200000000000_umx
)

# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------

add_subdirectory(mocks/bf_control_ops)
add_subdirectory(mocks/bf_debug_ops)
add_subdirectory(mocks/bf_syscall_impl)
add_subdirectory(mocks/bf_syscall_t)

add_subdirectory(src/bf_control_ops)
add_subdirectory(src/bf_debug_ops)
add_subdirectory(src/bf_syscall_impl)
add_subdirectory(src/bf_syscall_t)
