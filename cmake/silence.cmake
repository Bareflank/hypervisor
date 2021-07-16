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

include(${CMAKE_CURRENT_LIST_DIR}/function/hypervisor_silence.cmake)

hypervisor_silence(CMAKE_BUILD_TYPE)
hypervisor_silence(CMAKE_VERBOSE_MAKEFILE)
hypervisor_silence(CMAKE_TOOLCHAIN_FILE)
hypervisor_silence(CMAKE_C_COMPILER)
hypervisor_silence(CMAKE_CXX_COMPILER)
hypervisor_silence(CMAKE_INSTALL_MESSAGE)

hypervisor_silence(bsl_SOURCE_DIR)
hypervisor_silence(FETCHCONTENT_UPDATES_DISCONNECTED)
hypervisor_silence(FETCHCONTENT_SOURCE_DIR_BSL)

hypervisor_silence(BUILD_EXAMPLES)
hypervisor_silence(BUILD_TESTS)
hypervisor_silence(ENABLE_CLANG_FORMAT)
hypervisor_silence(ENABLE_DOXYGEN)
hypervisor_silence(ENABLE_COLOR)
hypervisor_silence(BSL_DEBUG_LEVEL)
hypervisor_silence(BSL_PAGE_SIZE)

hypervisor_silence(HYPERVISOR_EXTENSIONS)
hypervisor_silence(HYPERVISOR_EXTENSIONS_DIR)
hypervisor_silence(HYPERVISOR_TARGET_ARCH)
hypervisor_silence(HYPERVISOR_CXX_LINKER)
hypervisor_silence(HYPERVISOR_EFI_LINKER)
hypervisor_silence(HYPERVISOR_EFI_FS0)
hypervisor_silence(HYPERVISOR_PAGE_SIZE)
hypervisor_silence(HYPERVISOR_PAGE_SHIFT)

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    hypervisor_silence(HYPERVISOR_SERIAL_PORT)
else()
    hypervisor_silence(HYPERVISOR_SERIAL_PORTH)
    hypervisor_silence(HYPERVISOR_SERIAL_PORTL)
endif()

hypervisor_silence(HYPERVISOR_DEBUG_RING_SIZE)
hypervisor_silence(HYPERVISOR_VMEXIT_LOG_SIZE)
hypervisor_silence(HYPERVISOR_MAX_ELF_FILE_SIZE)
hypervisor_silence(HYPERVISOR_MAX_SEGMENTS)
hypervisor_silence(HYPERVISOR_MAX_EXTENSIONS)
hypervisor_silence(HYPERVISOR_MAX_PPS)
hypervisor_silence(HYPERVISOR_MAX_VMS)
hypervisor_silence(HYPERVISOR_MAX_VPS)
hypervisor_silence(HYPERVISOR_MAX_VPSS)
hypervisor_silence(HYPERVISOR_MK_DIRECT_MAP_ADDR)
hypervisor_silence(HYPERVISOR_MK_DIRECT_MAP_SIZE)
hypervisor_silence(HYPERVISOR_MK_STACK_ADDR)
hypervisor_silence(HYPERVISOR_MK_STACK_SIZE)
hypervisor_silence(HYPERVISOR_MK_CODE_ADDR)
hypervisor_silence(HYPERVISOR_MK_CODE_SIZE)
hypervisor_silence(HYPERVISOR_MK_PAGE_POOL_ADDR)
hypervisor_silence(HYPERVISOR_MK_PAGE_POOL_SIZE)
hypervisor_silence(HYPERVISOR_MK_HUGE_POOL_ADDR)
hypervisor_silence(HYPERVISOR_MK_HUGE_POOL_SIZE)
hypervisor_silence(HYPERVISOR_EXT_DIRECT_MAP_ADDR)
hypervisor_silence(HYPERVISOR_EXT_DIRECT_MAP_SIZE)
hypervisor_silence(HYPERVISOR_EXT_STACK_ADDR)
hypervisor_silence(HYPERVISOR_EXT_STACK_SIZE)
hypervisor_silence(HYPERVISOR_EXT_CODE_ADDR)
hypervisor_silence(HYPERVISOR_EXT_CODE_SIZE)
hypervisor_silence(HYPERVISOR_EXT_TLS_ADDR)
hypervisor_silence(HYPERVISOR_EXT_TLS_SIZE)
hypervisor_silence(HYPERVISOR_EXT_PAGE_POOL_ADDR)
hypervisor_silence(HYPERVISOR_EXT_PAGE_POOL_SIZE)
hypervisor_silence(HYPERVISOR_EXT_HUGE_POOL_ADDR)
hypervisor_silence(HYPERVISOR_EXT_HUGE_POOL_SIZE)
hypervisor_silence(HYPERVISOR_EXT_HEAP_POOL_ADDR)
hypervisor_silence(HYPERVISOR_EXT_HEAP_POOL_SIZE)
