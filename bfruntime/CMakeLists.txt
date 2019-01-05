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

cmake_minimum_required(VERSION 3.10)
project(bfruntime C CXX)

init_project(bfruntime INTERFACE)
target_link_libraries(bfruntime INTERFACE vmm::bfutil)

#
# Generator expressions
#
set(X64 $<STREQUAL:${BUILD_TARGET_ARCH},x86_64>)
set(ARM $<STREQUAL:${BUILD_TARGET_ARCH},aarch64>)
set(ASM $<AND:${X64},$<NOT:$<BOOL:${WIN32}>>>)
set(BUILD $<BOOL:$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>>)
set(C_CXX $<OR:$<COMPILE_LANGUAGE:C>,$<COMPILE_LANGUAGE:CXX>>)
set(BUILD_INCLUDE $<AND:${C_CXX},${BUILD}>)

#
# crt
#
add_library(bfcrt)
target_link_libraries(bfcrt PUBLIC vmm::bfruntime)
target_compile_options(bfcrt PRIVATE $<${C_CXX}:-Wno-main>)
target_sources(bfcrt PRIVATE
    src/crt/crt.cpp
    $<${X64}:src/crt/start_x64.asm>
    $<${ARM}:src/crt/start_x64.S>
)

#
# pthread
#
add_library(bfpthread)
target_link_libraries(bfpthread PUBLIC vmm::bfutil)
target_sources(bfpthread PRIVATE
    src/pthread/pthread.cpp
    $<${ASM}:src/pthread/threadcontext.asm>
)

#
# syscall
#
add_library(bfsyscall)
target_link_libraries(bfsyscall PUBLIC vmm::bfutil)
target_sources(bfsyscall PRIVATE src/syscall/syscall.cpp)

#
# unwind
#
add_library(bfunwind)
target_link_libraries(bfunwind PUBLIC vmm::bfutil)
target_include_directories(bfunwind PRIVATE
    $<${BUILD_INCLUDE}:${CMAKE_CURRENT_LIST_DIR}/src/unwind/include>
)
target_sources(bfunwind PRIVATE
    src/unwind/dwarf4.cpp
    src/unwind/eh_frame.cpp
    src/unwind/ia64_cxx_abi.cpp
    src/unwind/registers_intel_x64.asm
)

#
# install
#
install(
    FILES src/unwind/include/ia64_cxx_abi.h
    DESTINATION include
    RENAME unwind.h
)

install(TARGETS bfcrt DESTINATION lib EXPORT bfruntime-vmm-targets)
install(TARGETS bfpthread DESTINATION lib EXPORT bfruntime-vmm-targets)
install(TARGETS bfsyscall DESTINATION lib EXPORT bfruntime-vmm-targets)
install(TARGETS bfunwind DESTINATION lib EXPORT bfruntime-vmm-targets)

fini_project()
