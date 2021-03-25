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
    ${CMAKE_CURRENT_LIST_DIR}/../mocks
)

list(APPEND SYSTEM_INCLUDES
    ${CMAKE_SOURCE_DIR}/syscall/include/cpp
    ${CMAKE_SOURCE_DIR}/syscall/mocks/cpp
)

# ------------------------------------------------------------------------------
# Definitions
# ------------------------------------------------------------------------------

list(APPEND DEFINES
    HYPERVISOR_START_NAME=ut_start
    HYPERVISOR_STACK_CHK_FAIL_NAME=ut_stack_chk_fail
    HYPERVISOR_STACK_CHK_GUARD_NAME=ut_stack_chk_guard
    HYPERVISOR_MEMCPY_NAME=ut_memcpy
    HYPERVISOR_MEMSET_NAME=ut_memset
    HYPERVISOR_PRINT_THREAD_ID_NAME=ut_print_thread_id
    HYPERVISOR_PUTC_STDERR_NAME=ut_putc_stderr
    HYPERVISOR_PUTC_STDOUT_NAME=ut_putc_stdout
    HYPERVISOR_PUTS_STDERR_NAME=ut_puts_stderr
    HYPERVISOR_PUTS_STDOUT_NAME=ut_puts_stdout
)

# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------

add_subdirectory(src/bsl/cstdio)
add_subdirectory(src/bsl/details/print_thread_id)
add_subdirectory(src/bsl/details/putc_stderr)
add_subdirectory(src/bsl/details/putc_stdout)
add_subdirectory(src/bsl/details/puts_stderr)
add_subdirectory(src/bsl/details/puts_stdout)
add_subdirectory(src/__stack_chk_fail)

# NOTE:
# - We want to make sure that memcpy and memset are working properly as these
#   are hand written in assembly. We only need these to support SYSV, so for
#   now they are only tests under Linux, which is fine because CI will always
#   have a Linux component.
# - The bigger issue is that we have to test this code on each arch which is
#   something that we try to avoid under unit tests. Since we currently do not
#   have an ARM based CI environment, this code must be manually tested on ARM
#   for now. For now this is not much of an issue as the code that we are using
#   for ARM was actually written by ARM, not us.
#

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_subdirectory(src/_start)
    add_subdirectory(src/__stack_chk_guard)
    add_subdirectory(src/memcpy)
    add_subdirectory(src/memset)
endif()
