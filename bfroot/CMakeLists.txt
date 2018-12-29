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

# ------------------------------------------------------------------------------
# Generator expressions
# ------------------------------------------------------------------------------

# Common
set(C $<COMPILE_LANGUAGE:C>)
set(CXX $<COMPILE_LANGUAGE:CXX>)
set(C_CXX $<OR:${C},${CXX}>)
set(X64 $<STREQUAL:${BUILD_TARGET_ARCH},x86_64>)
set(C_CXX_X64 $<AND:${C_CXX},${X64}>)
set(MSVC $<CXX_COMPILER_ID:MSVC>)
set(CLANG $<CXX_COMPILER_ID:Clang>)
set(VMM $<AND:$<STREQUAL:${PREFIX},vmm>,$<BOOL:${BUILD_VMM}>>)
set(EFI $<AND:$<STREQUAL:${PREFIX},efi>,$<BOOL:${BUILD_EFI}>>)
set(TST $<AND:$<STREQUAL:${PREFIX},test>,$<BOOL:${BUILD_TEST}>>)
set(USR $<AND:$<STREQUAL:${PREFIX},userspace>,$<BOOL:${BUILD_USERSPACE}>>)

# VMM
set(VMM_CXX $<AND:${VMM},${CXX}>)
set(VMM_C_CXX $<AND:${VMM},${C_CXX}>)
set(VMM_C_CXX_CLANG $<AND:${VMM_C_CXX},${CLANG}>)
set(VMM_C_CXX_MSVC $<AND:${VMM_C_CXX},${MSVC}>)

# EFI
set(EFI_C $<AND:${EFI},${C}>)
set(EFI_C_CLANG $<AND:${EFI_C},${CLANG}>)
set(EFI_C_CXX $<AND:${EFI},${C_CXX}>)
set(EFI_C_CXX_CLANG $<AND:${EFI_C_CXX},${CLANG}>)

# Test
set(TST_C_CXX $<AND:${TST},${C_CXX}>)
set(TST_C_CXX_MSVC $<AND:${TST_C_CXX},${MSVC}>)
set(TST_CXX_CLANG $<AND:${TST},${CXX},${CLANG}>)
set(TST_C_CXX_CLANG $<AND:${TST_C_CXX},${CLANG}>)
set(TST_C_CXX_CLANG_ASAN $<AND:${TST_C_CXX_CLANG},$<BOOL:${ENABLE_ASAN}>>)
set(TST_C_CXX_CLANG_USAN $<AND:${TST_C_CXX_CLANG},$<BOOL:${ENABLE_USAN}>>)
set(TST_C_CXX_CLANG_CODECOV $<AND:${TST_C_CXX_CLANG},$<BOOL:${ENABLE_CODECOV}>>)

# Userspace
set(USR_C_CXX $<AND:${USR},${C_CXX}>)
set(USR_C_CXX_MSVC $<AND:${USR_C_CXX},${MSVC}>)
set(USR_CXX_CLANG $<AND:${USR},${CXX},${CLANG}>)
set(USR_C_CXX_CLANG $<AND:${USR_C_CXX},${CLANG}>)

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
    $<${CXX}:-std=c++17>
    $<${C}:-std=c11>
)

# ------------------------------------------------------------------------------
# Root interface for vmm prefix
# ------------------------------------------------------------------------------

if(PREFIX STREQUAL vmm)
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E make_directory ${VMM_PREFIX_PATH}/include/c++/v1
        COMMAND ${CMAKE_COMMAND} -E make_directory ${VMM_PREFIX_PATH}/lib
    )
endif()

target_compile_options(bfroot INTERFACE
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
target_compile_definitions(bfroot INTERFACE
    $<${VMM_C_CXX}:VMM>
    $<${VMM_C_CXX}:MALLOC_PROVIDED>
    $<${VMM_C_CXX}:CLOCK_MONOTONIC>
    $<${VMM_C_CXX}:_HAVE_LONG_DOUBLE>
    $<${VMM_C_CXX}:_LDBL_EQ_DBL>
    $<${VMM_C_CXX}:_POSIX_TIMERS>
    $<${VMM_C_CXX}:_POSIX_THREADS>
    $<${VMM_C_CXX}:_POSIX_PRIORITY_SCHEDULING>
    $<${VMM_C_CXX}:_UNIX98_THREAD_MUTEX_ATTRIBUTES>
    $<${VMM_C_CXX}:__SINGLE_THREAD__>
    $<${VMM_C_CXX}:__ELF__>
    $<${EFI_C_CXX}:BUILD_EFI>
)
target_include_directories(bfroot SYSTEM INTERFACE
    $<INSTALL_INTERFACE:$<${VMM_C_CXX}:${VMM_PREFIX_PATH}/include/c++/v1>>
    $<INSTALL_INTERFACE:$<${VMM_C_CXX}:${VMM_PREFIX_PATH}/include>>
)
target_link_directories(bfroot INTERFACE
    $<INSTALL_INTERFACE:$<${VMM_C_CXX}:${VMM_PREFIX_PATH}/lib>>
)
target_link_options(bfroot INTERFACE
    $<${VMM}:--sysroot=${VMM_PREFIX_PATH}>
    $<${VMM}:-z max-page-size=4096 "SHELL:-z common-page-size=4096" "SHELL:-z relro" "SHELL:-z now" >
    $<${VMM}:-nostdlib>
    $<${VMM}:-pie>
)

# ------------------------------------------------------------------------------
# Root interface for test prefix
# ------------------------------------------------------------------------------

if(PREFIX STREQUAL test)
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E make_directory ${TEST_PREFIX_PATH}/include
        COMMAND ${CMAKE_COMMAND} -E make_directory ${TEST_PREFIX_PATH}/lib
    )

    add_library(catch)
    target_sources(catch PRIVATE ${SOURCE_BFUTIL_DIR}/tests/test_catch.cpp)
    target_include_directories(catch PRIVATE
        $<BUILD_INTERFACE:$<${TST_C_CXX}:${TEST_PREFIX_PATH}/include>>
    )
    install(TARGETS catch DESTINATION lib EXPORT bfroot-test-targets)
    target_link_libraries(bfroot INTERFACE catch)
endif()

target_compile_options(bfroot INTERFACE
    $<${TST_C_CXX_CLANG}:-fpic>
    $<${TST_C_CXX_CLANG}:-fno-stack-protector>
    $<${TST_C_CXX_CLANG}:-fvisibility=hidden>
    $<${TST_C_CXX_CLANG}:-Wno-deprecated-declarations>
    $<${TST_CXX_CLANG}:-fvisibility-inlines-hidden>

    $<${TST_C_CXX_CLANG_ASAN}:-O1 -g -fno-omit-frame-pointer>
    $<${TST_C_CXX_CLANG_ASAN}:-fsanitize=address -fsanitize=leak -fuse-ld=gold>
    $<${TST_C_CXX_CLANG_USAN}:-fsanitize=undefined -fuse-ld=gold>
    $<${TST_C_CXX_CLANG_CODECOV}:-g -O0 -fprofile-arcs>
    $<${TST_C_CXX_CLANG_CODECOV}:-ftest-coverage -DDEBUG_LEVEL=5>

    $<${TST_C_CXX_MSVC}:/EHsc>
    $<${TST_C_CXX_MSVC}:/bigobj>
    $<${TST_C_CXX_MSVC}:/WX>
)
target_compile_definitions(bfroot INTERFACE
    $<${TST_C_CXX}:NATIVE>
    $<${TST_C_CXX}:BUILD_TEST>
    $<${TST_C_CXX_MSVC}:_SCL_SECURE_NO_WARNINGS>
    $<${TST_C_CXX_MSVC}:_CRT_SECURE_NO_WARNINGS>
    $<${TST_C_CXX_MSVC}:NOMINMAX>
)
target_include_directories(bfroot SYSTEM INTERFACE
    $<INSTALL_INTERFACE:$<${TST_C_CXX}:${TEST_PREFIX_PATH}/include>>
)
target_link_directories(bfroot INTERFACE
    $<INSTALL_INTERFACE:$<${TST_C_CXX}:${TEST_PREFIX_PATH}/lib>>
)

# ------------------------------------------------------------------------------
# Root interface for userspace prefix
# ------------------------------------------------------------------------------

if(PREFIX STREQUAL userspace)
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E make_directory ${USERSPACE_PREFIX_PATH}/include
    )
endif()

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
    $<INSTALL_INTERFACE:$<${USR_C_CXX}:${USERSPACE_PREFIX_PATH}/include>>
)

# ------------------------------------------------------------------------------
# Root interface for EFI prefix
# ------------------------------------------------------------------------------

if(PREFIX STREQUAL efi)
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E make_directory ${EFI_PREFIX_PATH}/include/efi/x86_64
    )
endif()

target_compile_options(bfroot INTERFACE
    $<${EFI_C_CLANG}:-mno-red-zone>
    $<${EFI_C_CLANG}:-mno-avx>
    $<${EFI_C_CLANG}:-g>
    $<${EFI_C_CLANG}:-O2>
    $<${EFI_C_CLANG}:-Wall>
    $<${EFI_C_CLANG}:-Wextra>
    $<${EFI_C_CLANG}:-Wno-error=pragmas>
    $<${EFI_C_CLANG}:-fshort-wchar>
    $<${EFI_C_CLANG}:-fno-strict-aliasing>
    $<${EFI_C_CLANG}:-ffreestanding>
    $<${EFI_C_CLANG}:-fno-stack-protector>
    $<${EFI_C_CLANG}:-fno-stack-check>
    $<${EFI_C_CLANG}:-fno-merge-all-constants>
    $<${EFI_C_CLANG}:-std=c11>
    $<${EFI_C_CLANG}:-U__linux__>
)
target_compile_definitions(bfroot INTERFACE
    $<${EFI_C_CLANG}:CONFIG_x86_64>
    $<${EFI_C_CLANG}:GNU_EFI_USE_MS_ABI>
    $<${EFI_C_CLANG}:__KERNEL__>
    $<${EFI_C_CLANG}:KERNEL>
    $<${EFI_C_CLANG}:EFI>
)
target_include_directories(bfroot SYSTEM INTERFACE
    $<INSTALL_INTERFACE:$<${EFI_C_CLANG}:${EFI_PREFIX_PATH}/include/efi>>
    $<INSTALL_INTERFACE:$<${EFI_C_CLANG}:${EFI_PREFIX_PATH}/include/efi/x86_64>>
)
