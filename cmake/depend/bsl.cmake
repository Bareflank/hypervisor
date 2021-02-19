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

FetchContent_Declare(
    bsl
    GIT_REPOSITORY  https://github.com/bareflank/bsl.git
    GIT_TAG         0406b10a6b6dacde00f0649ea37b42a2ba31362b
)

FetchContent_GetProperties(bsl)
if(NOT bsl_POPULATED)
    set(BSL_BUILD_EXAMPLES_OVERRIDE ON)
    set(BSL_BUILD_TESTS_OVERRIDE ON)
    set(BSL_INCLUDE_INFO_OVERRIDE ON)
    FetchContent_Populate(bsl)
    add_subdirectory(${bsl_SOURCE_DIR} ${bsl_BINARY_DIR})
endif()
