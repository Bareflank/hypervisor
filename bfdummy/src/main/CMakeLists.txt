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
