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
    if(NOT DEFINED ENV{CLANG_BIN})
        find_program(CLANG_BIN_60 clang-6.0)
        find_program(CLANG_BIN_50 clang-5.0)
        find_program(CLANG_BIN_40 clang-4.0)
        find_program(CLANG_BIN_39 clang-3.9)
        find_program(CLANG_BIN_38 clang-3.8)
        find_program(CLANG_BIN clang)
    else()
        set(CLANG_BIN $ENV{CLANG_BIN})
    endif()

    if(CLANG_BIN_60)
        set(CMAKE_C_COMPILER ${CLANG_BIN_60})
        set(CMAKE_CXX_COMPILER ${CLANG_BIN_60})
    elseif(CLANG_BIN_50)
        set(CMAKE_C_COMPILER ${CLANG_BIN_50})
        set(CMAKE_CXX_COMPILER ${CLANG_BIN_50})
    elseif(CLANG_BIN_40)
        set(CMAKE_C_COMPILER ${CLANG_BIN_40})
        set(CMAKE_CXX_COMPILER ${CLANG_BIN_40})
    elseif(CLANG_BIN_39)
        set(CMAKE_C_COMPILER ${CLANG_BIN_39})
        set(CMAKE_CXX_COMPILER ${CLANG_BIN_39})
    elseif(CLANG_BIN_38)
        set(CMAKE_C_COMPILER ${CLANG_BIN_38})
        set(CMAKE_CXX_COMPILER ${CLANG_BIN_38})
    elseif(CLANG_BIN)
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

string(CONCAT EFI_C_FLAGS
    "-mno-red-zone "
    "-mno-avx "
    "-fpic  "
    "-g "
    "-O2 "
    "-Wall "
    "-Wextra "
    "-fshort-wchar "
    "-fno-strict-aliasing "
    "-fno-merge-all-constants "
    "-ffreestanding "
    "-fno-stack-protector "
    "-fno-stack-check "
    "-DCONFIG_x86_64 "
    "-DGNU_EFI_USE_MS_ABI "
    "--std=c11 "
    "-D__KERNEL__ "
)

string(CONCAT EFI_LD_FLAGS
    "-nostdlib "
    "--warn-common "
    "--no-undefined "
    "--fatal-warnings "
    "-shared "
    "-Bsymbolic "
    "-defsym=EFI_SUBSYSTEM=0xa "
    "--no-undefined "
)

set(CMAKE_C_COMPILE_OBJECT "clang <DEFINES> <INCLUDES> ${EFI_C_FLAGS} -o <OBJECT> -c <SOURCE>")

set(CMAKE_SKIP_RPATH TRUE)
set(CMAKE_C_CREATE_SHARED_LIBRARY "ld ${EFI_LD_FLAGS} <OBJECTS> -o <TARGET> <LINK_LIBRARIES>")

set(CMAKE_C_COMPILER_WORKS 1)
set(CMAKE_CXX_COMPILER_WORKS 1)
