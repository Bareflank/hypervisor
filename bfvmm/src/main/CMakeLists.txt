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

add_executable(vmm)

target_link_libraries(vmm PUBLIC --whole-archive bfvmm_entry --no-whole-archive)
target_link_libraries(vmm PUBLIC bfvmm_hve)
target_link_libraries(vmm PUBLIC bfvmm_vcpu)
target_link_libraries(vmm PUBLIC bfvmm_memory_manager)
target_link_libraries(vmm PUBLIC bfvmm_debug)
target_link_libraries(vmm PUBLIC vmm::bfintrinsics)
target_link_libraries(vmm PUBLIC ${CMAKE_INSTALL_PREFIX}/lib/libc++.a)
target_link_libraries(vmm PUBLIC ${CMAKE_INSTALL_PREFIX}/lib/libc++abi.a)
target_link_libraries(vmm PUBLIC vmm::bfpthread)
target_link_libraries(vmm PUBLIC vmm::bfunwind)
target_link_libraries(vmm PUBLIC ${CMAKE_INSTALL_PREFIX}/lib/libm.a)
target_link_libraries(vmm PUBLIC ${CMAKE_INSTALL_PREFIX}/lib/libc.a)
target_link_libraries(vmm PUBLIC vmm::bfsyscall)
target_link_libraries(vmm PUBLIC --whole-archive vmm::bfcrt --no-whole-archive)
target_link_libraries(vmm PUBLIC --whole-archive vmm::bfdso --no-whole-archive)

set(X64 $<STREQUAL:${BUILD_TARGET_ARCH},x86_64>)
target_sources(vmm PRIVATE $<${X64}:arch/intel_x64/vcpu_factory.cpp>)

install(TARGETS vmm DESTINATION bin EXPORT bfvmm-vmm-targets)
