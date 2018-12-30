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

add_library(bfvmm_hve)
target_link_libraries(bfvmm_hve PUBLIC bfvmm)

set(X64 $<STREQUAL:${BUILD_TARGET_ARCH},x86_64>)
set(WIN $<BOOL:${WIN32}>)
set(MOCK $<BOOL:${ENABLE_MOCKING}>)
set(NEED_ASM $<AND:$<NOT:${WIN}>,$<NOT:${MOCK}>>)

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
    $<$<AND:${X64},${NEED_ASM}>:arch/intel_x64/exception.asm>
    $<$<AND:${X64},${NEED_ASM}>:arch/intel_x64/nmi.asm>
    $<$<AND:${X64},${NEED_ASM}>:arch/intel_x64/exit_handler_entry.asm>
    $<$<AND:${X64},${NEED_ASM}>:arch/intel_x64/vmcs_launch.asm>
    $<$<AND:${X64},${NEED_ASM}>:arch/intel_x64/vmcs_promote.asm>
    $<$<AND:${X64},${NEED_ASM}>:arch/intel_x64/vmcs_resume.asm>
)

install(TARGETS bfvmm_hve DESTINATION lib EXPORT bfvmm)
install(DIRECTORY ../../include/hve/ DESTINATION include/bfvmm/hve)
