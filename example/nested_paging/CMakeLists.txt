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

add_executable(example_nested_paging)

# ------------------------------------------------------------------------------
# Includes
# ------------------------------------------------------------------------------

target_include_directories(example_nested_paging PRIVATE
    .
)

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    target_include_directories(example_nested_paging PRIVATE
        x64
    )

    if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
        target_include_directories(example_nested_paging PRIVATE
            x64/amd
        )
    endif()

    if(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
        target_include_directories(example_nested_paging PRIVATE
            x64/intel
        )
    endif()
endif()

if(HYPERVISOR_TARGET_ARCH STREQUAL "aarch64")
    target_include_directories(example_nested_paging PRIVATE
        arm
    )

    if(HYPERVISOR_TARGET_ARCH STREQUAL "aarch64")
        target_include_directories(example_nested_paging PRIVATE
            arm/aarch64
        )
    endif()
endif()

# ------------------------------------------------------------------------------
# Headers
# ------------------------------------------------------------------------------

list(APPEND HEADERS
    ${CMAKE_CURRENT_LIST_DIR}/page_pool_t.hpp
)

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    list(APPEND HEADERS
        ${CMAKE_CURRENT_LIST_DIR}/x64/common_arch_support.hpp
        ${CMAKE_CURRENT_LIST_DIR}/x64/intrinsic_cpuid.hpp
        ${CMAKE_CURRENT_LIST_DIR}/x64/map_page_flags.hpp
        ${CMAKE_CURRENT_LIST_DIR}/x64/memory_type.hpp
        ${CMAKE_CURRENT_LIST_DIR}/x64/mtrrs_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/x64/range_t.hpp
    )

    if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
        list(APPEND HEADERS
            ${CMAKE_CURRENT_LIST_DIR}/x64/amd/arch_support.hpp
            ${CMAKE_CURRENT_LIST_DIR}/x64/amd/nested_page_table_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/x64/amd/npdpt_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/x64/amd/npdpte_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/x64/amd/npdt_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/x64/amd/npdte_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/x64/amd/npml4t_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/x64/amd/npml4te_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/x64/amd/npt_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/x64/amd/npte_t.hpp
        )
    endif()

    if(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
        list(APPEND HEADERS
            ${CMAKE_CURRENT_LIST_DIR}/x64/intel/arch_support.hpp
            ${CMAKE_CURRENT_LIST_DIR}/x64/intel/epdpt_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/x64/intel/epdpte_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/x64/intel/epdt_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/x64/intel/epdte_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/x64/intel/epml4t_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/x64/intel/epml4te_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/x64/intel/ept_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/x64/intel/epte_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/x64/intel/extended_page_table_t.hpp
        )
    endif()
endif()

if(HYPERVISOR_TARGET_ARCH STREQUAL "aarch64")
    list(APPEND HEADERS
        ${CMAKE_CURRENT_LIST_DIR}/arm/common_arch_support.hpp
    )

    if(HYPERVISOR_TARGET_ARCH STREQUAL "aarch64")
        list(APPEND HEADERS
            ${CMAKE_CURRENT_LIST_DIR}/arm/aarch64/arch_support.hpp
        )
    endif()
endif()

# ------------------------------------------------------------------------------
# Sources
# ------------------------------------------------------------------------------

target_sources(example_nested_paging PRIVATE
    main.cpp
)

set_property(SOURCE main.cpp APPEND PROPERTY OBJECT_DEPENDS ${HEADERS})

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    target_sources(example_nested_paging PRIVATE
        x64/intrinsic_cpuid.S
    )

    set_property(SOURCE x64/intrinsic_cpuid.S APPEND PROPERTY OBJECT_DEPENDS ${HEADERS})
endif()

# ------------------------------------------------------------------------------
# Libraries
# ------------------------------------------------------------------------------

target_link_libraries(example_nested_paging PRIVATE
    runtime
    bsl
    loader
    syscall
)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL RELEASE OR CMAKE_BUILD_TYPE STREQUAL MINSIZEREL)
    add_custom_command(TARGET example_nested_paging POST_BUILD COMMAND ${CMAKE_STRIP} example_nested_paging)
endif()

install(TARGETS example_nested_paging DESTINATION bin)
