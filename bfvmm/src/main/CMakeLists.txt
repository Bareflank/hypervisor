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

add_executable(vmm)

target_link_libraries(vmm PUBLIC bfvmm_entry bfvmm_hve bfvmm_vcpu)
target_link_libraries(vmm PUBLIC bfvmm_memory_manager bfvmm_debug)
target_link_libraries(vmm PUBLIC bfintrinsics)

target_link_libraries(vmm PUBLIC ${VMM_PREFIX_PATH}/lib/libc++.a)
target_link_libraries(vmm PUBLIC ${VMM_PREFIX_PATH}/lib/libc++abi.a)
target_link_libraries(vmm PUBLIC bfpthread bfunwind)
target_link_libraries(vmm PUBLIC ${VMM_PREFIX_PATH}/lib/libm.a)
target_link_libraries(vmm PUBLIC ${VMM_PREFIX_PATH}/lib/libc.a)
target_link_libraries(vmm PUBLIC bfsyscall bfcrt)

set(X64 $<STREQUAL:${BUILD_TARGET_ARCH},x86_64>)
target_sources(vmm PRIVATE $<${X64}:arch/intel_x64/vcpu_factory.cpp>)
install(TARGETS vmm DESTINATION bin EXPORT bfvmm)
