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

cmake_minimum_required(VERSION 3.13)
project(bfroot C CXX)

init_project(bfroot INTERFACE)

# ------------------------------------------------------------------------------
# Generator expressions
# ------------------------------------------------------------------------------

set(CYG $<BOOL:${CYGWIN}>)
set(X64 $<STREQUAL:${BUILD_TARGET_ARCH},x86_64>)

set(C $<COMPILE_LANGUAGE:C>)
set(CXX $<COMPILE_LANGUAGE:CXX>)
set(C_CXX $<OR:${C},${CXX}>)
set(X64 $<STREQUAL:${BUILD_TARGET_ARCH},x86_64>)
set(C_CXX_X64 $<AND:${C_CXX},${X64}>)

set(GNU $<CXX_COMPILER_ID:GNU>)
set(MSVC $<CXX_COMPILER_ID:MSVC>)
set(CLANG $<CXX_COMPILER_ID:Clang>)

set(VMM $<AND:$<STREQUAL:${PREFIX},vmm>,$<BOOL:${ENABLE_BUILD_VMM}>>)
set(EFI $<AND:$<STREQUAL:${PREFIX},efi>,$<BOOL:${ENABLE_BUILD_EFI}>>)
set(TST $<AND:$<STREQUAL:${PREFIX},test>,$<BOOL:${ENABLE_BUILD_TEST}>>)
set(USR $<AND:$<STREQUAL:${PREFIX},userspace>,$<BOOL:${ENABLE_BUILD_USERSPACE}>>)

set(VMM_CXX $<AND:${VMM},${CXX}>)
set(VMM_C_CXX $<AND:${VMM},${C_CXX}>)
set(VMM_C_CXX_CLANG $<AND:${VMM_C_CXX},${CLANG}>)

set(EFI_C $<AND:${EFI},${C}>)
set(EFI_C_CXX $<AND:${EFI},${C_CXX}>)

set(TST_C_CXX $<AND:${TST},${C_CXX}>)
set(TST_CXX $<AND:${TST},${CXX}>)
set(TST_CXX_GNU $<AND:${TST},${CXX},${GNU}>)
set(TST_CXX_CLANG $<AND:${TST},${CXX},${CLANG}>)
set(TST_CXX_CLANG_GNU $<AND:${TST},${CXX},$<OR:${CLANG},${GNU}>>)

set(TST_C_CXX_GNU $<AND:${TST_C_CXX},${GNU}>)
set(TST_C_CXX_MSVC $<AND:${TST_C_CXX},${MSVC}>)
set(TST_C_CXX_CLANG $<AND:${TST_C_CXX},${CLANG}>)
set(TST_C_CXX_CLANG_GNU $<AND:${TST_C_CXX},$<OR:${CLANG},${GNU}>>)

set(TST_C_CXX_ASAN $<AND:${TST_C_CXX_CLANG_GNU},$<BOOL:${ENABLE_ASAN}>>)
set(TST_C_CXX_USAN $<AND:${TST_C_CXX_CLANG_GNU},$<BOOL:${ENABLE_USAN}>>)
set(TST_C_CXX_CODECOV $<AND:${TST_C_CXX_CLANG_GNU},$<BOOL:${ENABLE_CODECOV}>>)
set(TST_C_CXX_GNU_ASAN $<AND:${TST_C_CXX_GNU},$<BOOL:${ENABLE_ASAN}>>)
set(TST_C_CXX_GNU_CODECOV $<AND:${TST_C_CXX_GNU},$<BOOL:${ENABLE_CODECOV}>>)

# Userspace
set(USR_CXX_CLANG_GNU $<AND:${USR},${CXX},$<OR:${CLANG},${GNU}>>)
set(USR_C_CXX $<AND:${USR},${C_CXX}>)
set(USR_C_CXX_MSVC $<AND:${USR_C_CXX},${MSVC}>)
set(USR_C_CXX_CLANG $<AND:${USR_C_CXX},${CLANG}>)
set(USR_C_CXX_CLANG_GNU $<AND:${USR_C_CXX},$<OR:${CLANG},${GNU}>>)

# ------------------------------------------------------------------------------
# Root interface for all prefixes
# ------------------------------------------------------------------------------

target_compile_features(bfroot INTERFACE $<$<NOT:${CYG}>:c_std_11 cxx_std_17>)

target_compile_definitions(bfroot INTERFACE
    $<${C_CXX}:GSL_THROW_ON_CONTRACT_VIOLATION>
    $<${C_CXX}:${OSTYPE}>
    $<${C_CXX}:${ABITYPE}>
)
target_compile_options(bfroot INTERFACE
    $<${C_CXX_X64}:-msse>
    $<${C_CXX_X64}:-msse2>
    $<${C_CXX_X64}:-msse3>
    $<${CYG}:-std=c11 -std=c++17>
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
    target_link_libraries(bfroot INTERFACE catch)
    target_sources(catch PRIVATE ${SOURCE_BFSDK_DIR}/tests/test_catch.cpp)
    target_include_directories(catch SYSTEM PUBLIC
        $<BUILD_INTERFACE:$<${TST_C_CXX}:${TEST_PREFIX_PATH}/include>>
    )

    install(TARGETS catch DESTINATION lib EXPORT bfroot-test-targets)
endif()

target_compile_options(bfroot INTERFACE
    $<${TST_CXX_CLANG_GNU}:-fvisibility-inlines-hidden>

    $<${TST_C_CXX_CLANG_GNU}:-fpic -fno-stack-protector>
    $<${TST_C_CXX_CLANG_GNU}:-fvisibility=hidden -Wno-deprecated-declarations>

    $<${TST_C_CXX_ASAN}:-O1 -g -fno-omit-frame-pointer>
    $<${TST_C_CXX_ASAN}:-fsanitize=address -fsanitize=leak>
    $<${TST_C_CXX_USAN}:-fsanitize=undefined>
    $<${TST_C_CXX_CODECOV}:-g -O0 -fprofile-arcs>
    $<${TST_C_CXX_CODECOV}:-ftest-coverage -DDEBUG_LEVEL=5>

    $<${TST_C_CXX_MSVC}:/EHsc>
    $<${TST_C_CXX_MSVC}:/bigobj>
    $<${TST_C_CXX_MSVC}:/WX>
)
target_compile_definitions(bfroot INTERFACE
    $<${TST_C_CXX}:NATIVE>
    $<${TST_C_CXX}:ENABLE_BUILD_TEST>
    $<${TST_C_CXX_MSVC}:_SCL_SECURE_NO_WARNINGS>
    $<${TST_C_CXX_MSVC}:_CRT_SECURE_NO_WARNINGS>
    $<${TST_C_CXX_MSVC}:NOMINMAX>
    $<${TST_C_CXX_MSVC}:_SILENCE_CXX17_UNCAUGHT_EXCEPTION_DEPRECATION_WARNING>
)
target_link_options(bfroot INTERFACE
    $<${TST_C_CXX_GNU_ASAN}:-fsanitize=address>
    $<${TST_C_CXX_GNU_CODECOV}:--coverage>
)
target_link_directories(bfroot INTERFACE
    $<INSTALL_INTERFACE:$<${TST_C_CXX}:${TEST_PREFIX_PATH}/lib>>
)
target_include_directories(bfroot SYSTEM INTERFACE
    $<INSTALL_INTERFACE:$<${TST_C_CXX}:${TEST_PREFIX_PATH}/include>>
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
    $<${USR_C_CXX_CLANG_GNU}:-fpic>
    $<${USR_C_CXX_CLANG_GNU}:-fstack-protector-strong>
    $<${USR_C_CXX_CLANG_GNU}:-fvisibility=hidden>
    $<${USR_C_CXX_CLANG_GNU}:-Wno-deprecated-declarations>
    $<${USR_CXX_CLANG_GNU}:-fvisibility-inlines-hidden>
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
    $<${EFI_C}:-mno-red-zone>
    $<${EFI_C}:-mno-avx>
    $<${EFI_C}:-g>
    $<${EFI_C}:-O2>
    $<${EFI_C}:-Wall>
    $<${EFI_C}:-Wextra>
    $<${EFI_C}:-Wno-error=pragmas>
    $<${EFI_C}:-fshort-wchar>
    $<${EFI_C}:-fno-strict-aliasing>
    $<${EFI_C}:-ffreestanding>
    $<${EFI_C}:-fno-stack-protector>
    $<${EFI_C}:-fno-stack-check>
    $<${EFI_C}:-fno-merge-all-constants>
    $<${EFI_C}:-std=c11>
    $<${EFI_C}:-U__linux__>
)
target_compile_definitions(bfroot INTERFACE
    $<${EFI_C}:CONFIG_x86_64>
    $<${EFI_C}:GNU_EFI_USE_MS_ABI>
    $<${EFI_C}:__KERNEL__>
    $<${EFI_C}:KERNEL>
    $<${EFI_C}:EFI>
)
target_include_directories(bfroot SYSTEM INTERFACE
    $<INSTALL_INTERFACE:$<${EFI_C}:${EFI_PREFIX_PATH}/include/efi>>
    $<INSTALL_INTERFACE:$<${EFI_C}:${EFI_PREFIX_PATH}/include/efi/x86_64>>
)

fini_project()
