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

list(APPEND COMMON_INCLUDES
    ${CMAKE_CURRENT_LIST_DIR}/../include
    ${CMAKE_CURRENT_LIST_DIR}/../mocks
    ${CMAKE_CURRENT_LIST_DIR}/include
    ${CMAKE_CURRENT_LIST_DIR}/src
)

list(APPEND COMMON_SYSTEM_INCLUDES
)

list(APPEND X64_INCLUDES
    ${CMAKE_CURRENT_LIST_DIR}/../include/x64
    ${CMAKE_CURRENT_LIST_DIR}/../mocks/x64
    ${COMMON_INCLUDES}
)

list(APPEND X64_SYSTEM_INCLUDES
    ${COMMON_SYSTEM_INCLUDES}
)

list(APPEND AMD_INCLUDES
    ${CMAKE_CURRENT_LIST_DIR}/../include/x64/amd
    ${CMAKE_CURRENT_LIST_DIR}/../mocks/x64/amd
    ${X64_INCLUDES}
)

list(APPEND AMD_SYSTEM_INCLUDES
    ${X64_SYSTEM_INCLUDES}
)

list(APPEND INTEL_INCLUDES
    ${CMAKE_CURRENT_LIST_DIR}/../include/x64/intel
    ${CMAKE_CURRENT_LIST_DIR}/../mocks/x64/intel
    ${X64_INCLUDES}
)

list(APPEND INTEL_SYSTEM_INCLUDES
    ${X64_SYSTEM_INCLUDES}
)

list(APPEND AARCH64_INCLUDES
    ${CMAKE_CURRENT_LIST_DIR}/../include/arm/aarch64
    ${CMAKE_CURRENT_LIST_DIR}/../mocks/arm/aarch64
    ${COMMON_INCLUDES}
)

list(APPEND AARCH64_SYSTEM_INCLUDES
    ${COMMON_SYSTEM_INCLUDES}
)

# ------------------------------------------------------------------------------
# Definitions
# ------------------------------------------------------------------------------

list(APPEND COMMON_DEFINES
    HYPERVISOR_PAGE_SIZE=0x1000_umx
    HYPERVISOR_MK_DIRECT_MAP_ADDR=0x1000_umx
    HYPERVISOR_MK_DIRECT_MAP_SIZE=0x0000200000000000_umx
    HYPERVISOR_EXT_PAGE_POOL_ADDR=0x0000200000000000_umx
)

list(APPEND X64_DEFINES
    ${COMMON_DEFINES}
)

list(APPEND AMD_DEFINES
    ${X64_DEFINES}
)

list(APPEND INTEL_DEFINES
    ${X64_DEFINES}
)

list(APPEND AARCH64_DEFINES
    ${COMMON_DEFINES}
)

# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------

add_subdirectory(include/basic_lock_guard_t)
add_subdirectory(include/basic_queue_t)

add_subdirectory(mocks/basic_ifmap_t)
add_subdirectory(mocks/basic_ioctl_t)
add_subdirectory(mocks/basic_page_pool_t)
add_subdirectory(mocks/basic_root_page_table_t)
add_subdirectory(mocks/basic_spinlock_t)

# if(WIN32)
#     add_subdirectory(src/windows/basic_ifmap_t)
#     add_subdirectory(src/windows/basic_ioctl_t)
# else()
#     add_subdirectory(src/linux/basic_ifmap_t)
#     add_subdirectory(src/linux/basic_ioctl_t)
# endif()

add_subdirectory(src/basic_page_pool_t)
add_subdirectory(src/basic_root_page_table_t)
add_subdirectory(src/basic_spinlock_t)
