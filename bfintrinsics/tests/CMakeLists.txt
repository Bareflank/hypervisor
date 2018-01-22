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

cmake_minimum_required(VERSION 3.6)
project(bfintrinsics_test C CXX)

include(${SOURCE_CMAKE_DIR}/project.cmake)
init_project()

do_test(test_cpuid_intel_x64 SOURCES arch/intel_x64/test_cpuid.cpp)
do_test(test_crs_intel_x64 SOURCES arch/intel_x64/test_crs.cpp)
do_test(test_msrs_intel_x64 SOURCES arch/intel_x64/test_msrs.cpp)
do_test(test_vmx_intel_x64 SOURCES arch/intel_x64/test_vmx.cpp)

do_test(test_16bit_control_fields SOURCES arch/intel_x64/vmcs/test_16bit_control_fields.cpp)
do_test(test_16bit_guest_state_fields SOURCES arch/intel_x64/vmcs/test_16bit_guest_state_fields.cpp)
do_test(test_16bit_host_state_fields SOURCES arch/intel_x64/vmcs/test_16bit_host_state_fields.cpp)
do_test(test_32bit_control_fields SOURCES arch/intel_x64/vmcs/test_32bit_control_fields.cpp)
do_test(test_32bit_guest_state_fields SOURCES arch/intel_x64/vmcs/test_32bit_guest_state_fields.cpp)
do_test(test_32bit_host_state_fields SOURCES arch/intel_x64/vmcs/test_32bit_host_state_fields.cpp)
do_test(test_32bit_read_only_data_fields SOURCES arch/intel_x64/vmcs/test_32bit_read_only_data_fields.cpp)
do_test(test_64bit_control_fields SOURCES arch/intel_x64/vmcs/test_64bit_control_fields.cpp)
do_test(test_64bit_guest_state_fields SOURCES arch/intel_x64/vmcs/test_64bit_guest_state_fields.cpp)
do_test(test_64bit_host_state_fields SOURCES arch/intel_x64/vmcs/test_64bit_host_state_fields.cpp)
do_test(test_64bit_read_only_data_fields SOURCES arch/intel_x64/vmcs/test_64bit_read_only_data_fields.cpp)
do_test(test_vmcs_debug SOURCES arch/intel_x64/vmcs/test_debug.cpp)
do_test(test_vmcs_helpers SOURCES arch/intel_x64/vmcs/test_helpers.cpp)
do_test(test_natural_width_control_fields SOURCES arch/intel_x64/vmcs/test_natural_width_control_fields.cpp)
do_test(test_natural_width_guest_state_fields SOURCES arch/intel_x64/vmcs/test_natural_width_guest_state_fields.cpp)
do_test(test_natural_width_host_state_fields SOURCES arch/intel_x64/vmcs/test_natural_width_host_state_fields.cpp)
do_test(test_natural_width_read_only_data_fields SOURCES arch/intel_x64/vmcs/test_natural_width_read_only_data_fields.cpp)

do_test(test_cache SOURCES arch/x64/test_cache.cpp)
do_test(test_cpuid SOURCES arch/x64/test_cpuid.cpp)
do_test(test_debug SOURCES arch/x64/test_debug.cpp)
do_test(test_gdt SOURCES arch/x64/test_gdt.cpp)
do_test(test_idt SOURCES arch/x64/test_idt.cpp)
do_test(test_msrs SOURCES arch/x64/test_msrs.cpp)
do_test(test_pm SOURCES arch/x64/test_pm.cpp)
do_test(test_portio SOURCES arch/x64/test_portio.cpp)
do_test(test_rdtsc SOURCES arch/x64/test_rdtsc.cpp)
do_test(test_rflags SOURCES arch/x64/test_rflags.cpp)
do_test(test_srs SOURCES arch/x64/test_srs.cpp)
do_test(test_tlb SOURCES arch/x64/test_tlb.cpp)
