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

if(CMAKE_INSTALL_PREFIX)
    set(ENV{CMAKE_INSTALL_PREFIX} "${CMAKE_INSTALL_PREFIX}")
else()
    set(CMAKE_INSTALL_PREFIX "$ENV{CMAKE_INSTALL_PREFIX}")
endif()

set(CMAKE_SYSTEM_NAME Linux)

if(NOT WIN32)
    if(NOT DEFINED ENV{CLANG_BIN})
        find_program(CLANG_BIN clang)
    else()
        set(CLANG_BIN $ENV{CLANG_BIN})
    endif()

    if(CLANG_BIN)
        set(CMAKE_C_COMPILER ${CLANG_BIN})
        set(CMAKE_CXX_COMPILER ${CLANG_BIN})
    else()
        message(FATAL_ERROR "Unable to find clang")
    endif()
endif()

string(CONCAT LD_FLAGS_PRE
    "-nostdlib "
    "-shared "
    "-Bsymbolic "
    "-no-undefined "
    "-L ${CMAKE_INSTALL_PREFIX}/lib "
    "${CMAKE_INSTALL_PREFIX}/lib/crt0-efi-x86_64.o "
)

string(CONCAT LD_FLAGS_POST
    "-lefi "
    "-lgnuefi "
    "-T ${CMAKE_INSTALL_PREFIX}/lib/elf_x86_64_efi.lds "
)

set(CMAKE_C_CREATE_SHARED_LIBRARY
    "ld ${LD_FLAGS_PRE} <OBJECTS> ${LD_FLAGS_POST} -o <TARGET>"
)

set(CMAKE_CXX_CREATE_SHARED_LIBRARY
    "ld ${LD_FLAGS_PRE} <OBJECTS> ${LD_FLAGS_POST} -o <TARGET>"
)

set(CMAKE_C_COMPILER_WORKS 1)
set(CMAKE_CXX_COMPILER_WORKS 1)
