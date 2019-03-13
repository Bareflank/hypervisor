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

# ------------------------------------------------------------------------------
# Only static builds are supported
# ------------------------------------------------------------------------------

if(BUILD_SHARED_LIBS)
    invalid_config("BUILD_SHARED_LIBS not supported")
endif()

# ------------------------------------------------------------------------------
# EFI build validation
# ------------------------------------------------------------------------------

if(ENABLE_BUILD_EFI AND NOT ENABLE_BUILD_VMM)
    invalid_config("ENABLE_BUILD_VMM must be enabled if ENABLE_BUILD_EFI is enabled")
endif()

# ------------------------------------------------------------------------------
# Developer Features
# ------------------------------------------------------------------------------

if(ENABLE_BUILD_USERSPACE)
    if(CMAKE_C_COMPILER_ID STREQUAL Clang)
        invalid_config("ENABLE_BUILD_USERSPACE is not supported with clang")
    endif()
endif()

if(ENABLE_BUILD_TEST)
    if(CMAKE_C_COMPILER_ID STREQUAL Clang)
        invalid_config("ENABLE_BUILD_TEST is not supported with clang")
    endif()
endif()

if(ENABLE_ASAN)
    if(ENABLE_USAN)
        invalid_config("ENABLE_USAN cannot be enabled if ENABLE_ASAN is enabled")
    endif()
    if(NOT ENABLE_BUILD_TEST)
        invalid_config("ENABLE_BUILD_TEST must be enabled if ENABLE_ASAN is enabled")
    endif()
    if(NOT CMAKE_C_COMPILER_ID STREQUAL GNU)
        invalid_config("Must use gcc if ENABLE_ASAN is enabled")
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
