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
project(bfdriver C CXX)

include_directories("include")

set(DRIVER_BUILD_CMD ${BF_SCRIPTS_DIR}/util/driver_build.sh ${CMAKE_SOURCE_DIR})
set(DRIVER_CLEAN_CMD ${BF_SCRIPTS_DIR}/util/driver_clean.sh ${CMAKE_SOURCE_DIR})
set(DRIVER_LOAD_CMD ${BF_SCRIPTS_DIR}/util/driver_load.sh ${CMAKE_SOURCE_DIR})
set(DRIVER_UNLOAD_CMD ${BF_SCRIPTS_DIR}/util/driver_unload.sh ${CMAKE_SOURCE_DIR})

execute_process(COMMAND ${DRIVER_BUILD_CMD})
add_custom_target(bfdriver_build COMMAND ${DRIVER_BUILD_CMD})
add_custom_target(bfdriver_clean COMMAND ${DRIVER_CLEAN_CMD})
add_custom_target(bfdriver_load COMMAND ${DRIVER_LOAD_CMD})
add_custom_target(bfdriver_unload COMMAND ${DRIVER_UNLOAD_CMD})

if(${BUILD_TARGET_OS} STREQUAL "Linux")
    install(
        PROGRAMS ${BF_SOURCE_DIR}/bfdriver/src/arch/linux/bareflank.ko
        DESTINATION ${BUILD_SYSROOT_OS}/lib
    )
elseif(${BUILD_TARGET_OS} STREQUAL "Windows")
    # TODO: Install bareflank.sys to ${BUILD_SYSROOT_OS}/lib
endif()
