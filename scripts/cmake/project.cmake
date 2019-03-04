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

string(REPLACE "|" ";" PROJECT_INCLUDE_LIST "${PROJECT_INCLUDE_LIST}")
foreach(file ${PROJECT_INCLUDE_LIST})
    include(${file})
endforeach(file)

file(STRINGS "${PKG_FILE}" pkg_list)

foreach(pkg IN LISTS pkg_list)
    find_package(${pkg} REQUIRED)
endforeach(pkg)

if(ENABLE_BUILD_TEST)
    enable_testing()
endif()

if(CMAKE_INSTALL_PREFIX STREQUAL "${VMM_PREFIX_PATH}")
    set(PREFIX "vmm")
elseif(CMAKE_INSTALL_PREFIX STREQUAL "${USERSPACE_PREFIX_PATH}")
    set(PREFIX "userspace")
elseif(CMAKE_INSTALL_PREFIX STREQUAL "${TEST_PREFIX_PATH}")
    set(PREFIX "test")
elseif(CMAKE_INSTALL_PREFIX STREQUAL "${EFI_PREFIX_PATH}")
    set(PREFIX "efi")
else()
    message(FATAL_ERROR "Invalid prefix: ${CMAKE_INSTALL_PREFIX}")
endif()
