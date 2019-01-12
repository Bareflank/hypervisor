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

if(DEFINED ENV{LD_BIN})
    set(LD_BIN $ENV{LD_BIN})
else()
    set(LD_BIN ${CMAKE_INSTALL_PREFIX}/bin/ld)
endif()

string(CONCAT LD_FLAGS
    "--sysroot=${CMAKE_INSTALL_PREFIX} "
    "-L ${CMAKE_INSTALL_PREFIX}/lib "
    "-z max-page-size=4096 "
    "-z common-page-size=4096 "
    "-z relro "
    "-z now "
    "-nostdlib "
)

if(EXISTS "${CMAKE_INSTALL_PREFIX}/lib/libbfdso_static.a")
    string(CONCAT LD_FLAGS
        "--whole-archive ${CMAKE_INSTALL_PREFIX}/lib/libbfdso_static.a --no-whole-archive "
    )
endif()

set(CMAKE_C_ARCHIVE_CREATE
    "ar qc <TARGET> <OBJECTS>"
)

set(CMAKE_CXX_ARCHIVE_CREATE
    "ar qc <TARGET> <OBJECTS>"
)

set(CMAKE_C_LINK_EXECUTABLE
    "${LD_BIN} ${LD_FLAGS} -pie <OBJECTS> -o <TARGET> <LINK_LIBRARIES>"
)

set(CMAKE_CXX_LINK_EXECUTABLE
    "${LD_BIN} ${LD_FLAGS} -pie <OBJECTS> -o <TARGET> <LINK_LIBRARIES>"
)

set(CMAKE_C_CREATE_SHARED_LIBRARY
    "${LD_BIN} ${LD_FLAGS} -shared <OBJECTS> -o <TARGET>"
)

set(CMAKE_CXX_CREATE_SHARED_LIBRARY
    "${LD_BIN} ${LD_FLAGS} -shared <OBJECTS> -o <TARGET>"
)

set(CMAKE_C_COMPILER_WORKS 1)
set(CMAKE_CXX_COMPILER_WORKS 1)
