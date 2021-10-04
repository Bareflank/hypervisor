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

include(${CMAKE_CURRENT_LIST_DIR}/../cmake/function/hypervisor_target_source.cmake)

add_library(runtime)

# ------------------------------------------------------------------------------
# Includes
# ------------------------------------------------------------------------------

target_include_directories(runtime PUBLIC
    src
)

# ------------------------------------------------------------------------------
# Headers
# ------------------------------------------------------------------------------

list(APPEND HEADERS
    ${CMAKE_CURRENT_LIST_DIR}/src/bsl/cstdio.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/bsl/cstdlib.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/bsl/details/print_thread_id.hpp
)

# ------------------------------------------------------------------------------
# Definitions
# ------------------------------------------------------------------------------

target_compile_definitions(runtime PUBLIC
    HYPERVISOR_STACK_CHK_FAIL_NAME=__stack_chk_fail
    HYPERVISOR_STACK_CHK_GUARD_NAME=__stack_chk_guard
    HYPERVISOR_START_NAME=_start
    HYPERVISOR_INTRINSIC_ASSERT_NAME=intrinsic_assert
    HYPERVISOR_MEMCPY_NAME=memcpy
    HYPERVISOR_MEMSET_NAME=memset
)

# ------------------------------------------------------------------------------
# Sources
# ------------------------------------------------------------------------------

hypervisor_target_source(runtime src/__stack_chk_fail.cpp ${HEADERS})

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    hypervisor_target_source(runtime src/x64/__stack_chk_guard.S ${HEADERS})
    hypervisor_target_source(runtime src/x64/_start.S ${HEADERS})
    hypervisor_target_source(runtime src/x64/intrinsic_assert.S ${HEADERS})
    hypervisor_target_source(runtime src/x64/memcpy.S ${HEADERS})
    hypervisor_target_source(runtime src/x64/memset.S ${HEADERS})
endif()

if(HYPERVISOR_TARGET_ARCH STREQUAL "aarch64")
    hypervisor_target_source(runtime src/arm/aarch64/__stack_chk_guard.S ${HEADERS})
    hypervisor_target_source(runtime src/arm/aarch64/_start.S ${HEADERS})
    hypervisor_target_source(runtime src/arm/aarch64/intrinsic_assert.S ${HEADERS})
    hypervisor_target_source(runtime src/arm/aarch64/memcpy.S ${HEADERS})
    hypervisor_target_source(runtime src/arm/aarch64/memset.S ${HEADERS})
endif()

# ------------------------------------------------------------------------------
# Libraries
# ------------------------------------------------------------------------------

target_link_libraries(runtime PRIVATE
    bsl
    syscall
)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(TARGETS runtime DESTINATION lib)
