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

# NOTE: If this file is updated to reference an external CMake variable be sure
# to define it in the call to ExternalProject_Add in the super-build's
# CMakeLists.txt.

# ------------------------------------------------------------------------------
# Helper generator expressions
# ------------------------------------------------------------------------------

set(C $<COMPILE_LANGUAGE:C>)
set(CXX $<COMPILE_LANGUAGE:CXX>)
set(C_OR_CXX $<OR:${C},${CXX}>)
set(COMP_IS_MSVC $<CXX_COMPILER_ID:MSVC>)
set(COMP_IS_CLANG $<CXX_COMPILER_ID:Clang>)
set(C_OR_CXX_AND_MSVC $<AND:${C_OR_CXX},${COMP_IS_MSVC}>)
set(C_OR_CXX_AND_CLANG $<AND:${C_OR_CXX},${COMP_IS_CLANG}>)
set(X64 $<STREQUAL:${BUILD_TARGET_ARCH},x86_64>)

# ------------------------------------------------------------------------------
# Root target interface
# ------------------------------------------------------------------------------

add_library(bfroot_${VMM_PREFIX} INTERFACE)

target_compile_definitions(bfroot_${VMM_PREFIX} INTERFACE
    $<${C_OR_CXX}:GSL_THROW_ON_CONTRACT_VIOLATION>
    $<${C_OR_CXX}:${OSTYPE}>
    $<${C_OR_CXX}:${ABITYPE}>
)
target_compile_options(bfroot_${VMM_PREFIX} INTERFACE
    $<$<AND:${X64},${C_OR_CXX}>:-msse>
    $<$<AND:${X64},${C_OR_CXX}>:-msse2>
    $<$<AND:${X64},${C_OR_CXX}>:-msse3>
    $<${C}:-std=c11>
    $<${CXX}:-std=c++17>
)

# ------------------------------------------------------------------------------
# Root vmm target interface
# ------------------------------------------------------------------------------

if(ENABLE_BUILD_VMM)
    add_library(bfroot_vmm INTERFACE)
    target_link_libraries(bfroot_vmm INTERFACE bfroot_${VMM_PREFIX})
    target_compile_options(bfroot_vmm INTERFACE
        $<${C_OR_CXX}:--target=${BUILD_TARGET_ARCH}-vmm-elf>
        $<${C_OR_CXX}:--sysroot=${VMM_PREFIX_PATH}>
        $<${C_OR_CXX}:-fpic>
        $<${C_OR_CXX}:-mno-red-zone>
        $<${C_OR_CXX}:-mstackrealign>
        $<${C_OR_CXX}:-fstack-protector-strong>
        $<${C_OR_CXX}:-U__STRICT_ANSI__>
        $<${C_OR_CXX}:-U__USER_LABEL_PREFIX__>
        $<${C_OR_CXX}:-D__USER_LABEL_PREFIX__=>
        $<${CXX}:-x c++>
    )
    execute_process(COMMAND
        ${CMAKE_COMMAND} -E make_directory ${VMM_PREFIX_PATH}/include/c++/v1
        ${CMAKE_COMMAND} -E make_directory ${VMM_PREFIX_PATH}/lib
    )
    target_include_directories(bfroot_vmm SYSTEM INTERFACE
        $<${C_OR_CXX}:${VMM_PREFIX_PATH}/include/c++/v1>
        $<${C_OR_CXX}:${VMM_PREFIX_PATH}/include>
    )
    target_compile_definitions(bfroot_vmm INTERFACE
        $<${C_OR_CXX}:VMM>
        $<${C_OR_CXX}:CLOCK_MONOTONIC>
        $<${C_OR_CXX}:_POSIX_THREADS>
        $<${C_OR_CXX}:_POSIX_TIMERS>
        $<${C_OR_CXX}:_HAVE_LONG_DOUBLE>
        $<${C_OR_CXX}:_LDBL_EQ_DBL>
        $<${C_OR_CXX}:_POSIX_PRIORITY_SCHEDULING>
        $<${C_OR_CXX}:_UNIX98_THREAD_MUTEX_ATTRIBUTES>
        $<${C_OR_CXX}:__SINGLE_THREAD__>
        $<${C_OR_CXX}:__ELF__>
        $<$<AND:${C_OR_CXX},$<BOOL:${ENABLE_BUILD_EFI}>>:ENABLE_BUILD_EFI>
    )
    install(TARGETS bfroot_vmm DESTINATION ${EXPORT_DIR} EXPORT bfroot-targets)
endif()

# ------------------------------------------------------------------------------
# Root test target interface
# ------------------------------------------------------------------------------

if(ENABLE_BUILD_TEST)
    add_library(bfroot_test INTERFACE)
    target_link_libraries(bfroot_test INTERFACE bfroot_${VMM_PREFIX})
    target_compile_options(bfroot_test INTERFACE
        $<${C_OR_CXX_AND_CLANG}:-fpic>
        $<${C_OR_CXX_AND_CLANG}:-fno-stack-protector>
        $<${C_OR_CXX_AND_CLANG}:-fvisibility=hidden>
        $<${C_OR_CXX_AND_CLANG}:-Wno-deprecated-declarations>

        $<${C_OR_CXX_AND_MSVC}:/EHsc>
        $<${C_OR_CXX_AND_MSVC}:/bigobj>
        $<${C_OR_CXX_AND_MSVC}:/WX>

        $<$<AND:${COMP_IS_CLANG},${CXX}>:-fvisibility-inlines-hidden>
        $<$<BOOL:${ENABLE_ASAN}>:-O1 -g -fno-omit-frame-pointer>
        $<$<BOOL:${ENABLE_ASAN}>:-fsanitize=address -fsanitize=leak>
        $<$<BOOL:${ENABLE_USAN}>:-fsanitize=undefined>
        $<$<BOOL:${ENABLE_CODECOV}>:-g -O0 -fprofile-arcs>
        $<$<BOOL:${ENABLE_CODECOV}>:-ftest-coverage -DDEBUG_LEVEL=5>
    )
    target_compile_definitions(bfroot_test INTERFACE
        $<${C_OR_CXX}:NATIVE>
        $<${C_OR_CXX}:ENABLE_BUILD_TEST>
        $<${C_OR_CXX_AND_MSVC}:_SCL_SECURE_NO_WARNINGS>
        $<${C_OR_CXX_AND_MSVC}:_CRT_SECURE_NO_WARNINGS>
        $<${C_OR_CXX_AND_MSVC}:NOMINMAX>
    )
    target_include_directories(bfroot_test SYSTEM INTERFACE
        $<${C_OR_CXX}:${TEST_PREFIX_PATH}/include/c++/v1>
        $<${C_OR_CXX}:${TEST_PREFIX_PATH}/include>
    )
    target_link_directories(bfroot_test INTERFACE
        $<${C_OR_CXX}:${TEST_PREFIX_PATH}/lib>
    )
    install(TARGETS bfroot_test DESTINATION ${EXPORT_DIR} EXPORT bfroot-targets)
endif()

# ------------------------------------------------------------------------------
# Root userspace target interface
# ------------------------------------------------------------------------------

if(ENABLE_BUILD_USERSPACE)
    add_library(bfroot_userspace INTERFACE)
    target_link_libraries(bfroot_userspace INTERFACE bfroot_${VMM_PREFIX})
    target_compile_options(bfroot_userspace INTERFACE
        $<${C_OR_CXX_AND_CLANG}:-fpic>
        $<${C_OR_CXX_AND_CLANG}:-fstack-protector-strong>
        $<${C_OR_CXX_AND_CLANG}:-fvisibility=hidden>
        $<${C_OR_CXX_AND_CLANG}:-Wno-deprecated-declarations>

        $<${C_OR_CXX_AND_MSVC}:/EHsc>
        $<${C_OR_CXX_AND_MSVC}:/bigobj>
        $<${C_OR_CXX_AND_MSVC}:/WX>

        $<$<AND:${COMP_IS_CLANG},${CXX}>:-fvisibility-inlines-hidden>
    )
    target_compile_definitions(bfroot_userspace INTERFACE
        $<${C_OR_CXX}:NATIVE>
        $<${C_OR_CXX_AND_MSVC}:_SCL_SECURE_NO_WARNINGS>
        $<${C_OR_CXX_AND_MSVC}:_CRT_SECURE_NO_WARNINGS>
        $<${C_OR_CXX_AND_MSVC}:NOMINMAX>
    )
    target_include_directories(bfroot_userspace SYSTEM INTERFACE
        $<${C_OR_CXX}:${USERSPACE_PREFIX_PATH}/include/c++/v1>
        $<${C_OR_CXX}:${USERSPACE_PREFIX_PATH}/include>
    )
    target_link_directories(bfroot_userspace INTERFACE
        $<${C_OR_CXX}:${USERSPACE_PREFIX_PATH}/lib>
    )
    install(TARGETS bfroot_userspace DESTINATION ${EXPORT_DIR} EXPORT bfroot-targets)
endif()

# ------------------------------------------------------------------------------
# Root target exports
# ------------------------------------------------------------------------------

install(TARGETS bfroot_${VMM_PREFIX} DESTINATION ${EXPORT_DIR} EXPORT bfroot-targets)
install(EXPORT bfroot-targets  DESTINATION ${EXPORT_DIR})
set(PROJ bfroot)
configure_file(
    ${SOURCE_CMAKE_DIR}/target-config.cmake.in
    ${EXPORT_DIR}/${PROJ}-config.cmake
    @ONLY
)
