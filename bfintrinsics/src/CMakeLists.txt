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

cmake_minimum_required(VERSION 3.10)
project(bfintrinsics C CXX)

init_project(bfintrinsics)

set(X64 $<STREQUAL:${BUILD_TARGET_ARCH},x86_64>)
set(VMM $<AND:$<STREQUAL:${PREFIX},vmm>,$<BOOL:${BUILD_VMM}>>)
set(VMM_X64 $<AND:${VMM},${X64}>)

target_link_libraries(bfintrinsics PUBLIC ${PREFIX}::bfutil)
target_sources(bfintrinsics PRIVATE
    $<${VMM_X64}:arch/x64/cache.asm>
    $<${VMM_X64}:arch/x64/cpuid.asm>
    $<${VMM_X64}:arch/x64/gdt.asm>
    $<${VMM_X64}:arch/x64/idt.asm>
    $<${VMM_X64}:arch/x64/msrs.asm>
    $<${VMM_X64}:arch/x64/pm.asm>
    $<${VMM_X64}:arch/x64/portio.asm>
    $<${VMM_X64}:arch/x64/rdtsc.asm>
    $<${VMM_X64}:arch/x64/rflags.asm>
    $<${VMM_X64}:arch/x64/srs.asm>
    $<${VMM_X64}:arch/x64/tlb.asm>
    $<${VMM_X64}:arch/intel_x64/barrier.asm>
    $<${VMM_X64}:arch/intel_x64/bit.asm>
    $<${VMM_X64}:arch/intel_x64/crs.asm>
    $<${VMM_X64}:arch/intel_x64/drs.asm>
    $<${VMM_X64}:arch/intel_x64/pause.asm>
    $<${VMM_X64}:arch/intel_x64/vmx.asm>
)

install(DIRECTORY ../include/ DESTINATION include)

fini_project()
