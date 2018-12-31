#
# Bareflank Hypervisor
# Copyright (C) 2018 Assured Information Security, Inc.
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

cmake_minimum_required(VERSION 3.10)
project(bfroot C CXX)

init_project(bfroot INTERFACE)

# ------------------------------------------------------------------------------
# Root interface for all prefixes
# ------------------------------------------------------------------------------

target_compile_definitions(bfroot INTERFACE
    $<${C_CXX}:GSL_THROW_ON_CONTRACT_VIOLATION>
    $<${C_CXX}:${OSTYPE}>
    $<${C_CXX}:${ABITYPE}>
)
target_compile_options(bfroot INTERFACE
    $<${C_CXX_X64}:-msse>
    $<${C_CXX_X64}:-msse2>
    $<${C_CXX_X64}:-msse3>
    $<${C}:-std=c11>
    $<${CXX}:-std=c++17>
)

# ------------------------------------------------------------------------------
# Root interface for vmm prefix
# ------------------------------------------------------------------------------

target_compile_options(bfroot INTERFACE
    $<${VMM_C_CXX}:--target=${BUILD_TARGET_ARCH}-vmm-elf>
    $<${VMM_C_CXX}:--sysroot=${VMM_PREFIX_PATH}>
    $<${VMM_C_CXX}:-fpic>
    $<${VMM_C_CXX}:-mno-red-zone>
    $<${VMM_C_CXX}:-mstackrealign>
    $<${VMM_C_CXX}:-fstack-protector-strong>
    $<${VMM_C_CXX}:-U__STRICT_ANSI__>
    $<${VMM_C_CXX}:-U__USER_LABEL_PREFIX__>
    $<${VMM_C_CXX}:-D__USER_LABEL_PREFIX__=>
    $<${VMM_CXX}:-x c++>
)

target_include_directories(bfroot SYSTEM INTERFACE
    $<${VMM_C_CXX}:${VMM_PREFIX_PATH}/include/c++/v1>
    $<${VMM_C_CXX}:${VMM_PREFIX_PATH}/include>
)
target_compile_definitions(bfroot INTERFACE
    $<${VMM_C_CXX}:VMM>
    $<${VMM_C_CXX}:CLOCK_MONOTONIC>
    $<${VMM_C_CXX}:_POSIX_THREADS>
    $<${VMM_C_CXX}:_POSIX_TIMERS>
    $<${VMM_C_CXX}:_HAVE_LONG_DOUBLE>
    $<${VMM_C_CXX}:_LDBL_EQ_DBL>
    $<${VMM_C_CXX}:_POSIX_PRIORITY_SCHEDULING>
    $<${VMM_C_CXX}:_UNIX98_THREAD_MUTEX_ATTRIBUTES>
    $<${VMM_C_CXX}:__SINGLE_THREAD__>
    $<${VMM_C_CXX}:__ELF__>
    $<${EFI_C_CXX}:BUILD_EFI>
)

# ------------------------------------------------------------------------------
# Root interface for test prefix
# ------------------------------------------------------------------------------

target_compile_options(bfroot INTERFACE
    $<${TST_C_CXX_CLANG}:-fpic>
    $<${TST_C_CXX_CLANG}:-fno-stack-protector>
    $<${TST_C_CXX_CLANG}:-fvisibility=hidden>
    $<${TST_C_CXX_CLANG}:-Wno-deprecated-declarations>
    $<${TST_CXX_CLANG}:-fvisibility-inlines-hidden>

    $<${TST_C_CXX_MSVC}:/EHsc>
    $<${TST_C_CXX_MSVC}:/bigobj>
    $<${TST_C_CXX_MSVC}:/WX>

    $<${TST_C_CXX_CLANG_ASAN}:-O1 -g -fno-omit-frame-pointer>
    $<${TST_C_CXX_CLANG_ASAN}:-fsanitize=address -fsanitize=leak>
    $<${TST_C_CXX_CLANG_USAN}:-fsanitize=undefined>
    $<${TST_C_CXX_CLANG_CODECOV}:-g -O0 -fprofile-arcs>
    $<${TST_C_CXX_CLANG_CODECOV}:-ftest-coverage -DDEBUG_LEVEL=5>
)
target_compile_definitions(bfroot INTERFACE
    $<${TST_C_CXX}:NATIVE>
    $<${TST_C_CXX}:BUILD_TEST>
    $<${TST_C_CXX_MSVC}:_SCL_SECURE_NO_WARNINGS>
    $<${TST_C_CXX_MSVC}:_CRT_SECURE_NO_WARNINGS>
    $<${TST_C_CXX_MSVC}:NOMINMAX>
)
target_include_directories(bfroot SYSTEM INTERFACE
    $<${TST_C_CXX}:${TEST_PREFIX_PATH}/include/c++/v1>
    $<${TST_C_CXX}:${TEST_PREFIX_PATH}/include>
)
target_link_directories(bfroot INTERFACE
    $<${TST_C_CXX}:${TEST_PREFIX_PATH}/lib>
)

# ------------------------------------------------------------------------------
# Root interface for userspace prefix
# ------------------------------------------------------------------------------

target_compile_options(bfroot INTERFACE
    $<${USR_C_CXX_CLANG}:-fpic>
    $<${USR_C_CXX_CLANG}:-fstack-protector-strong>
    $<${USR_C_CXX_CLANG}:-fvisibility=hidden>
    $<${USR_C_CXX_CLANG}:-Wno-deprecated-declarations>
    $<${USR_CXX_CLANG}:-fvisibility-inlines-hidden>

    $<${USR_C_CXX_MSVC}:/EHsc>
    $<${USR_C_CXX_MSVC}:/bigobj>
    $<${USR_C_CXX_MSVC}:/WX>
)
target_compile_definitions(bfroot INTERFACE
    $<${USR_C_CXX}:NATIVE>
    $<${USR_C_CXX_MSVC}:_SCL_SECURE_NO_WARNINGS>
    $<${USR_C_CXX_MSVC}:_CRT_SECURE_NO_WARNINGS>
    $<${USR_C_CXX_MSVC}:NOMINMAX>
)
target_include_directories(bfroot SYSTEM INTERFACE
    $<${USR_C_CXX}:${USERSPACE_PREFIX_PATH}/include/c++/v1>
    $<${USR_C_CXX}:${USERSPACE_PREFIX_PATH}/include>
)
target_link_directories(bfroot INTERFACE
    $<${USR_C_CXX}:${USERSPACE_PREFIX_PATH}/lib>
)

fini_project()
