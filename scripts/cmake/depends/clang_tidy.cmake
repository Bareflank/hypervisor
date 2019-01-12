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

if(ENABLE_TIDY)
    if(NOT CLANG_TIDY_BIN)
        find_program(CLANG_TIDY_BIN clang-tidy-6.0)

        if(NOT CLANG_TIDY_BIN)
            message(STATUS "Including dependency: clang-tidy")
            message(STATUS "*** FATAL ERROR: Clang Tidy 6.0 was not found. To Fix:")
            message(STATUS "  - install clang-tidy-6.0 or")
            message(STATUS "  - ln -s /usr/bin/clang-tidy /usr/bin/clang-tidy-6.0")
            message(FATAL_ERROR "Unable to find: clang-tidy")
        endif()
    endif()
endif()
