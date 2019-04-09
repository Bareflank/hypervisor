#
# Bareflank Hypervisor
# Copyright (C) 2019 Assured Information Security, Inc.
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
project(bfruntime C CXX)

init_project(bfruntime INTERFACE)

# -----------------------------------------------------------------------------
# Generator expressions
# -----------------------------------------------------------------------------

set(X64 $<STREQUAL:${BUILD_TARGET_ARCH},x86_64>)
set(ARM_ASM $<STREQUAL:${BUILD_TARGET_ARCH},aarch64>)
set(X64_ASM $<AND:${X64},$<NOT:$<BOOL:${WIN32}>>>)
set(BUILD $<BOOL:$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>>)
set(C_CXX $<OR:$<COMPILE_LANGUAGE:C>,$<COMPILE_LANGUAGE:CXX>>)
set(BUILD_INCLUDE $<AND:${C_CXX},${BUILD}>)
set(NOT_TEST $<NOT:$<STREQUAL:${PREFIX},test>>)

# -----------------------------------------------------------------------------
# Common
# -----------------------------------------------------------------------------

target_link_libraries(bfruntime INTERFACE ${PREFIX}::bfroot)
target_include_directories(bfruntime INTERFACE
    $<${BUILD_INCLUDE}:${CMAKE_CURRENT_LIST_DIR}/include>
    $<${BUILD_INCLUDE}:${CMAKE_CURRENT_LIST_DIR}/../bfsdk/include>
)

# -----------------------------------------------------------------------------
# crt
# -----------------------------------------------------------------------------

add_library(bfcrt)
target_link_libraries(bfcrt PUBLIC bfruntime)
target_sources(bfcrt PRIVATE
    src/crt/crt.cpp
    $<$<AND:${NOT_TEST},${X64_ASM}>:src/crt/start_x64.asm>
    $<$<AND:${NOT_TEST},${ARM_ASM}>:src/crt/start_x64.S>
)
target_compile_options(bfcrt PRIVATE $<$<AND:${NOT_TEST},${C_CXX}>:-Wno-main>)

if(PREFIX STREQUAL test)
    do_test(tests/crt/test_crt.cpp DEPENDS bfcrt)
    install(TARGETS bfcrt DESTINATION lib EXPORT bfruntime-test-targets)
    fini_project()
    return()
endif()

# -----------------------------------------------------------------------------
# dso
# -----------------------------------------------------------------------------

add_library(bfdso)
target_link_libraries(bfdso PUBLIC bfruntime)
target_sources(bfdso PRIVATE src/dso/dso.cpp)

# -----------------------------------------------------------------------------
# pthread
# -----------------------------------------------------------------------------

add_library(bfpthread)
target_link_libraries(bfpthread PUBLIC bfruntime)
target_sources(bfpthread PRIVATE
    src/pthread/pthread.cpp
    $<$<AND:${NOT_TEST},${X64_ASM}>:src/pthread/threadcontext.asm>
)

# -----------------------------------------------------------------------------
# syscall
# -----------------------------------------------------------------------------

add_library(bfsyscall)
target_link_libraries(bfsyscall PUBLIC bfruntime)
target_sources(bfsyscall PRIVATE src/syscall/syscall.cpp)

# -----------------------------------------------------------------------------
# install
# -----------------------------------------------------------------------------

install(TARGETS bfcrt DESTINATION lib EXPORT bfruntime-${PREFIX}-targets)
install(TARGETS bfdso DESTINATION lib EXPORT bfruntime-${PREFIX}-targets)
install(TARGETS bfpthread DESTINATION lib EXPORT bfruntime-${PREFIX}-targets)
install(TARGETS bfsyscall DESTINATION lib EXPORT bfruntime-${PREFIX}-targets)

fini_project()
