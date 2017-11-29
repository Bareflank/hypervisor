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

if(${PROJECT_NAME} STREQUAL bfvmm_test)

    list(APPEND SOURCES
        cache_x64_mock.cpp
        cpuid_x64_mock.cpp
        crs_intel_x64_mock.cpp
        debug_x64_mock.cpp
        gdt_x64_mock.cpp
        idt_x64_mock.cpp
        msrs_x64_mock.cpp
        pm_x64_mock.cpp
        portio_x64_mock.cpp
        rdtsc_x64_mock.cpp
        rflags_x64_mock.cpp
        srs_x64_mock.cpp
        thread_context_x64_mock.cpp
        tlb_x64_mock.cpp
        vmx_intel_x64_mock.cpp
    )

else()

    list(APPEND SOURCES
        cache_x64.asm
        cpuid_x64.asm
        crs_intel_x64.asm
        debug_x64.asm
        gdt_x64.asm
        idt_x64.asm
        msrs_x64.asm
        pm_x64.asm
        portio_x64.asm
        rdtsc_x64.asm
        rflags_x64.asm
        srs_x64.asm
        thread_context_x64.asm
        tlb_x64.asm
        vmx_intel_x64.asm
    )

endif()

if(BUILD_VMM_SHARED)
    add_library(bfvmm_intrinsics_shared SHARED ${SOURCES})
    set_target_properties(bfvmm_intrinsics_shared PROPERTIES OUTPUT_NAME "bfvmm_intrinsics")
    set_target_properties(bfvmm_intrinsics_shared PROPERTIES LINKER_LANGUAGE C)
    target_compile_definitions(bfvmm_intrinsics_shared PRIVATE SHARED_INTRINSICS)
    install(TARGETS bfvmm_intrinsics_shared DESTINATION ${BUILD_SYSROOT_VMM}/lib)
endif()

if(BUILD_VMM_STATIC)
    add_library(bfvmm_intrinsics_static STATIC ${SOURCES})
    set_target_properties(bfvmm_intrinsics_static PROPERTIES OUTPUT_NAME "bfvmm_intrinsics")
    set_target_properties(bfvmm_intrinsics_static PROPERTIES LINKER_LANGUAGE C)
    target_compile_definitions(bfvmm_intrinsics_static PUBLIC STATIC_INTRINSICS)
    install(TARGETS bfvmm_intrinsics_static DESTINATION ${BUILD_SYSROOT_VMM}/lib)
endif()
