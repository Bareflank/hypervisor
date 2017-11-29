#
# Bareflank Hypervisor
# Copyright (C) 2015 Assured Information Security, Inc.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
#

include(${BF_FLAGS_DIR}/vmm_flags.cmake)
include(${BF_FLAGS_DIR}/userspace_flags.cmake)
include(${BF_FLAGS_DIR}/warning_flags.cmake)
include(${BF_FLAGS_DIR}/codecov_flags.cmake)
include(${BF_FLAGS_DIR}/asan_flags.cmake)
include(${BF_FLAGS_DIR}/usan_flags.cmake)

# Generates the appropriate C and C++ compiler flags for the current build
# configuruation, and the given environment (VMM or USERSPACE)
# @arg VMM: Set to generate flags for vmm components
# @arg USERSPACE: Set to generate flags for userspace components
# @arg SILENT: Set to silence flag debug output
# @arg C_FLAGS_OUT: Name of a cmake variable to contain C compiler flags as
#       output from this function. If not specified, CMAKE_C_FLAGS is used
# @arg CXX_FLAGS_OUT: Name of a cmake variable to contain C++ compiler flags as
#       output from this function. If not specified, CMAKE_CXX_FLAGS is used
# @arg ADD_C_FLAGS: Additional C flags added to the generated flags
# @arg ADD_CXX_FLAGS: Additional C++ flags added to the generated flags
function(generate_flags)
    set(options VMM USERSPACE)
    set(oneVal C_FLAGS_OUT CXX_FLAGS_OUT VERBOSE)
    set(multiVal ADD_C_FLAGS ADD_CXX_FLAGS)
    cmake_parse_arguments(GENERATE_FLAGS "${options}" "${oneVal}" "${multiVal}" ${ARGN})

    if(GENERATE_FLAGS_VMM AND GENERATE_FLAGS_USERSPACE)
        message(FATAL_ERROR "Cannot generate flags for both USERSPACE and VMM")
    endif()

    if(GENERATE_FLAGS_VMM)
        list(APPEND _C_FLAGS ${BFFLAGS_VMM} ${BFFLAGS_VMM_C} ${C_FLAGS_VMM})
        list(APPEND _CXX_FLAGS ${BFFLAGS_VMM} ${BFFLAGS_VMM_CXX} ${CXX_FLAGS_VMM})
        if(${BUILD_TARGET_ARCH} STREQUAL "x86_64")
            list(APPEND _C_FLAGS ${BFFLAGS_VMM_X86_64})
            list(APPEND _CXX_FLAGS ${BFFLAGS_VMM_X86_64})
        endif()
        if(${BUILD_TARGET_ARCH} STREQUAL "aarch64")
            list(APPEND _C_FLAGS ${BFFLAGS_VMM_AARCH64})
            list(APPEND _CXX_FLAGS ${BFFLAGS_VMM_AARCH64})
        endif()
    elseif(GENERATE_FLAGS_USERSPACE)
        list(APPEND _C_FLAGS ${BFFLAGS_USERSPACE} ${BFFLAGS_USERSPACE_C} ${C_FLAGS_USERSPACE})
        list(APPEND _CXX_FLAGS ${BFFLAGS_USERSPACE} ${BFFLAGS_USERSPACE_CXX} ${CXX_FLAGS_USERSPACE})
        if(${BUILD_TARGET_ARCH} STREQUAL "x86_64")
            list(APPEND _C_FLAGS ${BFFLAGS_USERSPACE_X86_64})
            list(APPEND _CXX_FLAGS ${BFFLAGS_USERSPACE_X86_64})
        endif()
        if(${BUILD_TARGET_ARCH} STREQUAL "aarch64")
            list(APPEND _C_FLAGS ${BFFLAGS_USERSPACE_AARCH64})
            list(APPEND _CXX_FLAGS ${BFFLAGS_USERSPACE_AARCH64})
        endif()

        if(ENABLE_ASAN)
            list(APPEND _C_FLAGS ${BFFLAGS_ASAN})
            list(APPEND _CXX_FLAGS ${BFFLAGS_ASAN})
        endif()

        if(ENABLE_USAN)
            list(APPEND _C_FLAGS ${BFFLAGS_USAN})
            list(APPEND _CXX_FLAGS ${BFFLAGS_USAN})
        endif()

        if(ENABLE_CODECOV)
            list(APPEND _C_FLAGS ${BFFLAGS_CODECOV_C})
            list(APPEND _CXX_FLAGS ${BFFLAGS_CODECOV_CXX})
        endif()
    else()
        message(FATAL_ERROR "Must specify either VMM or USERSPACE flags")
    endif()

    if(ENABLE_COMPILER_WARNINGS)
        list(APPEND _C_FLAGS ${BFFLAGS_WARNING_C})
        list(APPEND _CXX_FLAGS ${BFFLAGS_WARNING_CXX})
    endif()

    list(APPEND _C_FLAGS ${GENERATE_FLAGS_ADD_C_FLAGS})
    list(APPEND _CXX_FLAGS ${GENERATE_FLAGS_ADD_CXX_FLAGS})

    string(REPLACE ";" " " _C_FLAGS " ${_C_FLAGS}")
    string(REPLACE ";" " " _CXX_FLAGS " ${_CXX_FLAGS}")

    if(GENERATE_FLAGS_VERBOSE)
        message(STATUS "${PROJECT_NAME} C Flags: ${_C_FLAGS}")
        message(STATUS "${PROJECT_NAME} C++ Flags: ${_CXX_FLAGS}")
    endif()

    if(GENERATE_FLAGS_C_FLAGS_OUT)
        set(${GENERATE_FLAGS_C_FLAGS_OUT} ${_C_FLAGS} PARENT_SCOPE)
    else()
        set(CMAKE_C_FLAGS ${_C_FLAGS} PARENT_SCOPE)
    endif()

    if(GENERATE_FLAGS_CXX_FLAGS_OUT)
        set(${GENERATE_FLAGS_CXX_FLAGS_OUT} ${_CXX_FLAGS} PARENT_SCOPE)
    else()
        set(CMAKE_CXX_FLAGS ${_CXX_FLAGS} PARENT_SCOPE)
    endif()
endfunction(generate_flags)
