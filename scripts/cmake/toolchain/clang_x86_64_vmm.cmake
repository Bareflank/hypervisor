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

if(CMAKE_INSTALL_PREFIX)
    set(ENV{CMAKE_INSTALL_PREFIX} "${CMAKE_INSTALL_PREFIX}")
else()
    set(CMAKE_INSTALL_PREFIX "$ENV{CMAKE_INSTALL_PREFIX}")
endif()

set(CMAKE_SYSTEM_NAME Linux)

if(NOT WIN32)
    find_program(CLANG_BIN_40 clang-4.0)
    find_program(CLANG_BIN_39 clang-3.9)
    find_program(CLANG_BIN_38 clang-3.8)

    if(CLANG_BIN_40)
        set(CMAKE_C_COMPILER ${CLANG_BIN_40})
        set(CMAKE_CXX_COMPILER ${CLANG_BIN_40})
    elseif(CLANG_BIN_39)
        set(CMAKE_C_COMPILER ${CLANG_BIN_39})
        set(CMAKE_CXX_COMPILER ${CLANG_BIN_39})
    elseif(CLANG_BIN_38)
        set(CMAKE_C_COMPILER ${CLANG_BIN_38})
        set(CMAKE_CXX_COMPILER ${CLANG_BIN_38})
    else()
        message(FATAL_ERROR "Unable to find clang 3.8, 3.9 or 4.0")
    endif()
endif()

set(LD_FLAGS
    "--sysroot=${CMAKE_INSTALL_PREFIX} -L${CMAKE_INSTALL_PREFIX}/lib -z max-page-size=4096 -z common-page-size=4096 -z relro -z now -nostdlib"
)

set(CMAKE_C_LINK_EXECUTABLE
	"${CMAKE_INSTALL_PREFIX}/bin/ld ${LD_FLAGS} -pie <OBJECTS> -o <TARGET> <LINK_LIBRARIES>"
)

set(CMAKE_CXX_LINK_EXECUTABLE
	"${CMAKE_INSTALL_PREFIX}/bin/ld ${LD_FLAGS} -pie <OBJECTS> -o <TARGET> <LINK_LIBRARIES>"
)

set(CMAKE_C_ARCHIVE_CREATE
    "${CMAKE_INSTALL_PREFIX}/bin/ar qc <TARGET> <OBJECTS>"
)

set(CMAKE_CXX_ARCHIVE_CREATE
    "${CMAKE_INSTALL_PREFIX}/bin/ar qc <TARGET> <OBJECTS>"
)

set(CMAKE_C_CREATE_SHARED_LIBRARY
    "${CMAKE_INSTALL_PREFIX}/bin/ld ${LD_FLAGS} -shared -o <TARGET> <OBJECTS>"
)

set(CMAKE_CXX_CREATE_SHARED_LIBRARY
    "${CMAKE_INSTALL_PREFIX}/bin/ld ${LD_FLAGS} -shared -o <TARGET> <OBJECTS>"
)
