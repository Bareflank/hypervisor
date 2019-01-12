#
# Copyright (C) 2019 Assured Information Security, Inc.
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

cmake_minimum_required(VERSION 3.6)
project(bfdummy_main C CXX)

include(${SOURCE_CMAKE_DIR}/project.cmake)
init_project(
    INCLUDES ../../include
    TIDY_EXCLUSIONS -cppcoreguidelines-no-malloc
)

list(APPEND LIBRARIES
    dummy_lib1
    dummy_lib2
)

add_vmm_executable(dummy_main
    SOURCES dummy_main.cpp
    LIBRARIES ${LIBRARIES}
    NOVMMLIBS
)

add_vmm_executable(dummy_main_init_fails
    SOURCES dummy_main.cpp
    LIBRARIES ${LIBRARIES}
    DEFINES REQUEST_INIT_FAILS
    NOVMMLIBS
)

add_vmm_executable(dummy_main_fini_fails
    SOURCES dummy_main.cpp
    LIBRARIES ${LIBRARIES}
    DEFINES REQUEST_FINI_FAILS
    NOVMMLIBS
)

add_vmm_executable(dummy_main_add_mdl_fails
    SOURCES dummy_main.cpp
    LIBRARIES ${LIBRARIES}
    DEFINES REQUEST_ADD_MDL_FAILS
    NOVMMLIBS
)

add_vmm_executable(dummy_main_get_drr_fails
    SOURCES dummy_main.cpp
    LIBRARIES ${LIBRARIES}
    DEFINES REQUEST_GET_DRR_FAILS
    NOVMMLIBS
)

add_vmm_executable(dummy_main_set_rsdp_fails
    SOURCES dummy_main.cpp
    LIBRARIES ${LIBRARIES}
    DEFINES REQUEST_SET_RSDP_FAILS
    NOVMMLIBS
)

add_vmm_executable(dummy_main_vmm_init_fails
    SOURCES dummy_main.cpp
    LIBRARIES ${LIBRARIES}
    DEFINES REQUEST_VMM_INIT_FAILS
    NOVMMLIBS
)

add_vmm_executable(dummy_main_vmm_fini_fails
    SOURCES dummy_main.cpp
    LIBRARIES ${LIBRARIES}
    DEFINES REQUEST_VMM_FINI_FAILS
    NOVMMLIBS
)
