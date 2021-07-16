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

if(HYPERVISOR_TARGET_ARCH STREQUAL "aarch64")
    if(HYPERVISOR_BUILD_VMMCTL)
        message(FATAL_ERROR "HYPERVISOR_BUILD_VMMCTL is not supported on ARM")
    endif()
endif()

list(LENGTH HYPERVISOR_EXTENSIONS HYPERVISOR_EXTENSIONS_LENGTH)
if(NOT HYPERVISOR_EXTENSIONS_LENGTH EQUAL 1)
    message(FATAL_ERROR "More than one extension is currently not supported")
endif()

if(NOT EXISTS "${HYPERVISOR_EXTENSIONS_DIR}")
    message(FATAL_ERROR "HYPERVISOR_EXTENSIONS_DIR does not exist: ${HYPERVISOR_EXTENSIONS_DIR}")
endif()

if(NOT EXISTS "${HYPERVISOR_EXTENSIONS_DIR}/CMakeLists.txt")
    message(FATAL_ERROR "HYPERVISOR_EXTENSIONS_DIR does not contain a CMakeLists.txt")
endif()

if(HYPERVISOR_DEBUG_RING_SIZE LESS 0x1000)
    message(FATAL_ERROR "HYPERVISOR_DEBUG_RING_SIZE must be at least a page")
endif()

if(HYPERVISOR_VMEXIT_LOG_SIZE LESS 1)
    message(FATAL_ERROR "HYPERVISOR_VMEXIT_LOG_SIZE must be at least 1")
endif()

if(HYPERVISOR_MAX_SEGMENTS LESS 2)
    message(FATAL_ERROR "HYPERVISOR_MAX_SEGMENTS must be at least 2")
endif()

if(HYPERVISOR_MAX_EXTENSIONS LESS 1)
    message(FATAL_ERROR "HYPERVISOR_MAX_EXTENSIONS must be at least 1")
endif()

if(HYPERVISOR_MAX_PPS LESS 1)
    message(FATAL_ERROR "HYPERVISOR_MAX_PPS must be at least 1")
endif()

if(HYPERVISOR_MAX_VMS LESS 1)
    message(FATAL_ERROR "HYPERVISOR_MAX_VMS must be at least 1")
endif()

if(HYPERVISOR_MAX_VPS LESS HYPERVISOR_MAX_PPS)
    message(FATAL_ERROR "HYPERVISOR_MAX_VPS the same or greater as HYPERVISOR_MAX_PPS")
endif()

if(HYPERVISOR_MAX_VPSS LESS HYPERVISOR_MAX_VPS)
    message(FATAL_ERROR "HYPERVISOR_MAX_VPSS the same or greater as HYPERVISOR_MAX_VPS")
endif()

if(HYPERVISOR_MK_STACK_SIZE LESS 0x1000)
    message(FATAL_ERROR "HYPERVISOR_MK_STACK_SIZE must be at least a page")
endif()

if(HYPERVISOR_MK_PAGE_POOL_SIZE LESS 0x1000)
    message(FATAL_ERROR "HYPERVISOR_MK_PAGE_POOL_SIZE must be at least a page")
endif()

if(HYPERVISOR_MK_HUGE_POOL_SIZE LESS 0x1000)
    message(FATAL_ERROR "HYPERVISOR_MK_HUGE_POOL_SIZE must be at least a page")
endif()

if(HYPERVISOR_EXT_STACK_SIZE LESS 0x1000)
    message(FATAL_ERROR "HYPERVISOR_EXT_STACK_SIZE must be at least a page")
endif()
