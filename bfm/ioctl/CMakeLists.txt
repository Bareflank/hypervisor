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

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

if(NOT CYGWIN AND NOT WIN32)
    list(APPEND SOURCES
        arch/linux/ioctl.cpp
        arch/linux/ioctl_private.cpp
    )
    include_directories(arch/linux/)
else()
    list(APPEND SOURCES
        arch/windows/ioctl.cpp
        arch/windows/ioctl_private.cpp
    )
    include_directories(arch/windows/)
endif()

add_library(bfm_ioctl OBJECT ${SOURCES})
target_compile_definitions(bfm_ioctl PUBLIC STATIC_BFM_IOCTL)

add_library(bf_ioctl SHARED ${SOURCES})
target_compile_definitions(bf_ioctl PUBLIC SHARED_BFM_IOCTL)

if(CYGWIN OR WIN32)
    target_link_libraries(bf_ioctl setupapi)
endif()

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(TARGETS bf_ioctl DESTINATION ${BUILD_SYSROOT_OS}/lib)
