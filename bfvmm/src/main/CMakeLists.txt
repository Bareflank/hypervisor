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

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie")

if(NOT EXISTS ${CMAKE_BINARY_DIR}/null.cpp)
    file(WRITE
        ${CMAKE_BINARY_DIR}/null.cpp ""
    )
endif()

list(APPEND SOURCES
    main.cpp
)

add_library(bfvmm_main STATIC ${SOURCES})
install(TARGETS bfvmm_main DESTINATION ${BUILD_SYSROOT_VMM}/lib)

if(BUILD_VMM_SHARED)
    add_executable(bfvmm_shared ${CMAKE_BINARY_DIR}/null.cpp)
    target_link_libraries(bfvmm_shared -Wl,--whole-archive bfvmm_main -Wl,--no-whole-archive)
    target_link_libraries(bfvmm_shared bfvmm_vcpu_factory_shared)
    target_link_libraries(bfvmm_shared bfvmm_vcpu_shared)
    target_link_libraries(bfvmm_shared bfvmm_vcpu_manager_shared)
    target_link_libraries(bfvmm_shared bfvmm_exit_handler_shared)
    target_link_libraries(bfvmm_shared bfvmm_vmcs_shared)
    target_link_libraries(bfvmm_shared bfvmm_vmxon_shared)
    target_link_libraries(bfvmm_shared bfvmm_memory_manager_shared)
    target_link_libraries(bfvmm_shared bfvmm_support_shared)
    target_link_libraries(bfvmm_shared bfvmm_serial_shared)
    target_link_libraries(bfvmm_shared bfvmm_debug_ring_shared)
    target_link_libraries(bfvmm_shared bfvmm_intrinsics_shared)
    target_link_libraries(bfvmm_shared c++)
    target_link_libraries(bfvmm_shared c++abi)
    target_link_libraries(bfvmm_shared pthread)
    target_link_libraries(bfvmm_shared bfunwind)
    target_link_libraries(bfvmm_shared --whole-archive -lbfcrt --no-whole-archive)
    target_link_libraries(bfvmm_shared c)
    target_link_libraries(bfvmm_shared bfsyscall)
    install(TARGETS bfvmm_shared DESTINATION ${BUILD_SYSROOT_VMM}/bin)
endif()

if(BUILD_VMM_STATIC)
    add_executable(bfvmm_static ${CMAKE_BINARY_DIR}/null.cpp)
    target_link_libraries(bfvmm_static -Wl,--whole-archive bfvmm_main -Wl,--no-whole-archive)
    target_link_libraries(bfvmm_static -Wl,--whole-archive bfvmm_vcpu_factory_static -Wl,--no-whole-archive)
    target_link_libraries(bfvmm_static -Wl,--whole-archive bfvmm_vcpu_static -Wl,--no-whole-archive)
    target_link_libraries(bfvmm_static -Wl,--whole-archive bfvmm_vcpu_manager_static -Wl,--no-whole-archive)
    target_link_libraries(bfvmm_static bfvmm_exit_handler_static)
    target_link_libraries(bfvmm_static bfvmm_vmcs_static)
    target_link_libraries(bfvmm_static bfvmm_vmxon_static)
    target_link_libraries(bfvmm_static -Wl,--whole-archive bfvmm_memory_manager_static -Wl,--no-whole-archive)
    target_link_libraries(bfvmm_static bfvmm_support_static)
    target_link_libraries(bfvmm_static bfvmm_serial_static)
    target_link_libraries(bfvmm_static bfvmm_debug_ring_static)
    target_link_libraries(bfvmm_static bfvmm_intrinsics_static)
    target_link_libraries(bfvmm_static c++)
    target_link_libraries(bfvmm_static c++abi)
    target_link_libraries(bfvmm_static pthread)
    target_link_libraries(bfvmm_static bfunwind)
    target_link_libraries(bfvmm_static --whole-archive -lbfcrt --no-whole-archive)
    target_link_libraries(bfvmm_static c)
    target_link_libraries(bfvmm_static bfsyscall)
    install(TARGETS bfvmm_static DESTINATION ${BUILD_SYSROOT_VMM}/bin)
endif()
