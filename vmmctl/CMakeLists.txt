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

add_executable(vmmctl)

# ------------------------------------------------------------------------------
# Includes
# ------------------------------------------------------------------------------

target_include_directories(vmmctl PRIVATE
    src
    $<$<PLATFORM_ID:Linux>:${CMAKE_CURRENT_LIST_DIR}/src/linux>
    $<$<PLATFORM_ID:Windows>:${CMAKE_CURRENT_LIST_DIR}/src/windows>
)

target_include_directories(vmmctl SYSTEM PRIVATE
    ${CMAKE_BINARY_DIR}/include
)

# ------------------------------------------------------------------------------
# Headers
# ------------------------------------------------------------------------------

list(APPEND HEADERS
    ${CMAKE_CURRENT_LIST_DIR}/src/linux/ifmap.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/linux/ioctl.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/windows/ifmap.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/windows/ioctl.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/vmmctl_main.hpp
)

# ------------------------------------------------------------------------------
# Sources
# ------------------------------------------------------------------------------

hypervisor_target_source(vmmctl src/main.cpp ${HEADERS})

# ------------------------------------------------------------------------------
# Libraries
# ------------------------------------------------------------------------------

target_link_libraries(vmmctl PRIVATE
    bsl
    loader
    hypervisor
    $<$<PLATFORM_ID:Windows>:SetupAPI>
    $<$<PLATFORM_ID:Windows>:libcmt.lib>
)

# ------------------------------------------------------------------------------
# Options
# ------------------------------------------------------------------------------

target_compile_options(vmmctl PRIVATE
    -Wno-frame-larger-than=
)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(TARGETS vmmctl DESTINATION bin)
