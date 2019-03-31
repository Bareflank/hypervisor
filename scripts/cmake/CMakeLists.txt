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

cmake_minimum_required(VERSION 3.13)
project(bfroot C CXX)

init_project(bfroot INTERFACE)

# ------------------------------------------------------------------------------
# Generator expressions
# ------------------------------------------------------------------------------

set(X64 $<STREQUAL:${BUILD_TARGET_ARCH},x86_64>)

set(C $<COMPILE_LANGUAGE:C>)
set(CXX $<COMPILE_LANGUAGE:CXX>)
set(C_CXX $<OR:${C},${CXX}>)
set(C_CXX_X64 $<AND:${C_CXX},${X64}>)
set(CXX_X64 $<AND:${CXX},${X64}>)

set(GNU $<CXX_COMPILER_ID:GNU>)
set(MSVC $<CXX_COMPILER_ID:MSVC>)
set(CLANG $<CXX_COMPILER_ID:Clang>)

set(GNU_CLANG $<OR:${GNU},${CLANG}>)
set(GNU_CLANG_C $<AND:${GNU_CLANG},${C}>)
set(GNU_CLANG_CXX $<AND:${GNU_CLANG},${CXX}>)
set(GNU_CLANG_C_CXX_X64 $<AND:${C_CXX_X64},${GNU_CLANG}>)
set(MSVC_C_CXX $<AND:${MSVC},${C_CXX}>)

set(VMM $<STREQUAL:${PREFIX},vmm>)
set(EFI $<STREQUAL:${PREFIX},efi>)
set(TST $<STREQUAL:${PREFIX},test>)
set(USR $<STREQUAL:${PREFIX},userspace>)

# VMM
set(VMM_CXX $<AND:${VMM},${CXX}>)
set(VMM_C_CXX $<AND:${VMM},${C_CXX}>)
set(VMM_C_CXX_CLANG $<AND:${VMM_C_CXX},${CLANG}>)

# EFI
set(EFI_C $<AND:${EFI},${C}>)
set(EFI_C_CXX $<AND:${EFI},${C_CXX}>)

# Test
set(TST_C_CXX $<AND:${TST},${C_CXX}>)
set(TST_CXX $<AND:${TST},${CXX}>)
set(TST_CXX_GNU $<AND:${TST_CXX},${GNU}>)
set(TST_C_CXX_GNU $<AND:${TST_C_CXX},${GNU}>)
set(TST_C_CXX_MSVC $<AND:${TST_C_CXX},${MSVC}>)
set(TST_C_CXX_ASAN $<AND:${TST_C_CXX_GNU},$<BOOL:${ENABLE_ASAN}>>)
set(TST_C_CXX_USAN $<AND:${TST_C_CXX_GNU},$<BOOL:${ENABLE_USAN}>>)
set(TST_C_CXX_CODECOV $<AND:${TST_C_CXX_GNU},$<BOOL:${ENABLE_CODECOV}>>)

# Userspace
set(USR_C_CXX $<AND:${USR},${C_CXX}>)
set(USR_C_CXX_GNU $<AND:${USR_C_CXX},${GNU}>)
set(USR_C_CXX_MSVC $<AND:${USR_C_CXX},${MSVC}>)
set(USR_CXX_GNU $<AND:${USR},${CXX},${GNU}>)

# ------------------------------------------------------------------------------
# Root interface for all prefixes
# ------------------------------------------------------------------------------

target_compile_definitions(bfroot INTERFACE
    $<${C_CXX}:GSL_THROW_ON_CONTRACT_VIOLATION>
    $<${C_CXX}:${OSTYPE}>
    $<${C_CXX}:${ABITYPE}>
)
target_compile_options(bfroot INTERFACE
    $<${GNU_CLANG_C}:-std=c11>
    $<${GNU_CLANG_CXX}:-std=c++17>
    $<${GNU_CLANG_C_CXX_X64}:-msse>
    $<${GNU_CLANG_C_CXX_X64}:-msse2>
    $<${GNU_CLANG_C_CXX_X64}:-msse3>
    $<${MSVC_C_CXX}:/std:c++17>
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
    $<${TST_CXX_GNU}:-fvisibility-inlines-hidden>
    $<${TST_C_CXX_GNU}:-fpic -fno-stack-protector>
    $<${TST_C_CXX_GNU}:-fvisibility=hidden -Wno-deprecated-declarations>
    $<${TST_C_CXX_ASAN}:-O1 -fno-omit-frame-pointer>
    $<${TST_C_CXX_ASAN}:-fuse-ld=gold -fsanitize=address -fsanitize=leak>
    $<${TST_C_CXX_USAN}:-fuse-ld=gold -fsanitize=undefined>
    $<${TST_C_CXX_CODECOV}:-O0 -fprofile-arcs -ftest-coverage>
    $<${TST_C_CXX_MSVC}:/EHsc>
    $<${TST_C_CXX_MSVC}:/bigobj>
    $<${TST_C_CXX_MSVC}:/WX>
)
target_compile_definitions(bfroot INTERFACE
    $<${TST_C_CXX}:NATIVE>
    $<${TST_C_CXX}:ENABLE_BUILD_TEST>
    $<${TST_C_CXX_CODECOV}:DEBUG_LEVEL=5>
    $<${TST_C_CXX_MSVC}:_SCL_SECURE_NO_WARNINGS>
    $<${TST_C_CXX_MSVC}:_CRT_SECURE_NO_WARNINGS>
    $<${TST_C_CXX_MSVC}:NOMINMAX>
    $<${TST_C_CXX_MSVC}:_SILENCE_CXX17_UNCAUGHT_EXCEPTION_DEPRECATION_WARNING>
)
target_link_options(bfroot INTERFACE
    $<${TST_C_CXX_ASAN}:-fuse-ld=gold -fsanitize=address>
    $<${TST_C_CXX_USAN}:-fuse-ld=gold -fsanitize=undefined>
    $<${TST_C_CXX_CODECOV}:--coverage>
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
    $<${USR_CXX_GNU}:-fvisibility-inlines-hidden>
    $<${USR_C_CXX_GNU}:-fpic>
    $<${USR_C_CXX_GNU}:-fstack-protector-strong>
    $<${USR_C_CXX_GNU}:-fvisibility=hidden>
    $<${USR_C_CXX_GNU}:-Wno-deprecated-declarations>
    $<${USR_C_CXX_MSVC}:/EHsc>
    $<${USR_C_CXX_MSVC}:/bigobj>
    $<${USR_C_CXX_MSVC}:/WX>
)
target_compile_definitions(bfroot INTERFACE
    $<${USR_C_CXX}:NATIVE>
    $<${USR_C_CXX_MSVC}:_SCL_SECURE_NO_WARNINGS>
    $<${USR_C_CXX_MSVC}:_CRT_SECURE_NO_WARNINGS>
    $<${USR_C_CXX_MSVC}:NOMINMAX>
    $<${USR_C_CXX_MSVC}:_SILENCE_CXX17_UNCAUGHT_EXCEPTION_DEPRECATION_WARNING>
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
