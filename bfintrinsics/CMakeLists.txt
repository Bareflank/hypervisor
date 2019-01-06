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
project(bfintrinsics C CXX)

set(X64 $<STREQUAL:${BUILD_TARGET_ARCH},x86_64>)

init_project(bfintrinsics)
target_link_libraries(bfintrinsics PUBLIC ${PREFIX}::bfroot)
target_sources(bfintrinsics PRIVATE
    $<${X64}:src/arch/x64/cache.asm>
    $<${X64}:src/arch/x64/cpuid.asm>
    $<${X64}:src/arch/x64/gdt.asm>
    $<${X64}:src/arch/x64/idt.asm>
    $<${X64}:src/arch/x64/msrs.asm>
    $<${X64}:src/arch/x64/pm.asm>
    $<${X64}:src/arch/x64/portio.asm>
    $<${X64}:src/arch/x64/rdtsc.asm>
    $<${X64}:src/arch/x64/rflags.asm>
    $<${X64}:src/arch/x64/srs.asm>
    $<${X64}:src/arch/x64/tlb.asm>
    $<${X64}:src/arch/intel_x64/barrier.asm>
    $<${X64}:src/arch/intel_x64/bit.asm>
    $<${X64}:src/arch/intel_x64/crs.asm>
    $<${X64}:src/arch/intel_x64/drs.asm>
    $<${X64}:src/arch/intel_x64/pause.asm>
    $<${X64}:src/arch/intel_x64/vmx.asm>
)

#install(DIRECTORY include/ DESTINATION include)

fini_project()
