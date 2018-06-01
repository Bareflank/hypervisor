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
# Unit Testing
# ------------------------------------------------------------------------------

if(ENABLE_BUILD_TEST AND NOT BUILD_SHARED_LIBS)
    invalid_config("BUILD_SHARED_LIBS must be enabled if ENABLE_BUILD_TEST is enabled")
endif()

# ------------------------------------------------------------------------------
# VMM build type
# ------------------------------------------------------------------------------

if(NOT BUILD_SHARED_LIBS AND NOT BUILD_STATIC_LIBS)
    invalid_config("BUILD_SHARED_LIBS or BUILD_STATIC_LIBS must be enabled")
endif()

# ------------------------------------------------------------------------------
# EFI build validation
# ------------------------------------------------------------------------------

if (ENABLE_BUILD_EFI AND NOT BUILD_STATIC_LIBS)
    invalid_config("BUILD_STATIC_LIBS must be enabled to build EFI-bootable vmm (ENABLE_BUILD_EFI)")
endif()

if (ENABLE_BUILD_EFI AND NOT ENABLE_BUILD_VMM)
    invalid_config("ENABLE_BUILD_VMM must be enabled to build EFI-bootable vmm (ENABLE_BUILD_EFI)")
endif()

# ------------------------------------------------------------------------------
# Developer Features
# ------------------------------------------------------------------------------

if(ENABLE_ASAN)
    if(ENABLE_USAN)
        invalid_config("ENABLE_USAN cannot be enabled if ENABLE_ASAN is enabled")
    endif()
    if(NOT ENABLE_BUILD_TEST)
        invalid_config("ENABLE_BUILD_TEST must be enabled if ENABLE_ASAN is enabled")
    endif()
endif()

if(ENABLE_USAN)
    if(ENABLE_ASAN)
        invalid_config("ENABLE_ASAN cannot be enabled if ENABLE_USAN is enabled")
    endif()
    if(NOT ENABLE_BUILD_TEST)
        invalid_config("ENABLE_BUILD_TEST must be enabled if ENABLE_USAN is enabled")
    endif()
endif()

if(ENABLE_CODECOV)
    if(NOT ENABLE_BUILD_TEST)
        invalid_config("ENABLE_BUILD_TEST must be enabled if ENABLE_CODECOV is enabled")
    endif()
endif()

if(ENABLE_TIDY)
    if(NOT ENABLE_BUILD_TEST)
        invalid_config("ENABLE_BUILD_TEST must be enabled if ENABLE_TIDY is enabled")
    endif()
endif()

# ------------------------------------------------------------------------------
# Windows build rules
# ------------------------------------------------------------------------------

if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
    if(ENABLE_BUILD_VMM)
        invalid_config("ENABLE_BUILD_VMM is not supported on Windows")
    endif()
    if(ENABLE_ASAN)
        invalid_config("ENABLE_ASAN is not supported on Windows")
    endif()
    if(ENABLE_USAN)
        invalid_config("ENABLE_USAN is not supported on Windows")
    endif()
    if(ENABLE_TIDY)
        invalid_config("ENABLE_TIDY is not supported on Windows")
    endif()
    if(ENABLE_CODECOV)
        invalid_config("ENABLE_CODECOV is not supported on Windows")
    endif()
endif()

if(CMAKE_HOST_SYSTEM_NAME STREQUAL "CYGWIN")
    if(ENABLE_ASAN)
        invalid_config("ENABLE_ASAN is not supported on Cygwin")
    endif()
    if(ENABLE_USAN)
        invalid_config("ENABLE_USAN is not supported on Cygwin")
    endif()
    if(ENABLE_TIDY)
        invalid_config("ENABLE_TIDY is not supported on Cygwin")
    endif()
    if(ENABLE_CODECOV)
        invalid_config("ENABLE_CODECOV is not supported on Cygwin")
    endif()
endif()

# ------------------------------------------------------------------------------
# Cygwin build rules
# ------------------------------------------------------------------------------

if(CMAKE_HOST_SYSTEM_NAME STREQUAL "CYGWIN")
    if(ENABLE_ASAN)
        invalid_config("ENABLE_ASAN is not supported on Cygwin")
    endif()
    if(ENABLE_USAN)
        invalid_config("ENABLE_USAN is not supported on Cygwin")
    endif()
    if(ENABLE_CODECOV)
        invalid_config("ENABLE_CODECOV is not supported on Cygwin")
    endif()
endif()
