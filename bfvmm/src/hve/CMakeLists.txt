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

set(WIN $<BOOL:${WIN32}>)
set(X64 $<STREQUAL:${BUILD_TARGET_ARCH},x86_64>)
set(MOCK $<BOOL:${ENABLE_MOCKING}>)
set(X64_ASM $<AND:$<NOT:${WIN}>,$<NOT:${MOCK}>,${X64}>)

add_library(bfvmm_hve)

target_link_libraries(bfvmm_hve PUBLIC ${PREFIX}::bfvmm)
target_sources(bfvmm_hve PRIVATE
    $<${X64}:arch/intel_x64/check_vmcs_control_fields.cpp>
    $<${X64}:arch/intel_x64/check_vmcs_guest_fields.cpp>
    $<${X64}:arch/intel_x64/check_vmcs_host_fields.cpp>
    $<${X64}:arch/intel_x64/exception.cpp>
    $<${X64}:arch/intel_x64/nmi.cpp>
    $<${X64}:arch/intel_x64/exit_handler.cpp>
    $<${X64}:arch/intel_x64/vcpu.cpp>
    $<${X64}:arch/intel_x64/vmcs.cpp>
    $<${X64}:arch/intel_x64/vmx.cpp>
    $<${X64_ASM}:arch/intel_x64/exception.asm>
    $<${X64_ASM}:arch/intel_x64/nmi.asm>
    $<${X64_ASM}:arch/intel_x64/exit_handler_entry.asm>
    $<${X64_ASM}:arch/intel_x64/vmcs_launch.asm>
    $<${X64_ASM}:arch/intel_x64/vmcs_promote.asm>
    $<${X64_ASM}:arch/intel_x64/vmcs_resume.asm>
)

install(TARGETS bfvmm_hve DESTINATION lib EXPORT bfvmm-${PREFIX}-targets)

if(PREFIX STREQUAL vmm)
    install(DIRECTORY ../../include/hve/ DESTINATION include/bfvmm/hve)
endif()
