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

macro(do_test str)
    add_executable(test_${str} test_${str}.cpp)
    target_compile_definitions(test_${str} PRIVATE STATIC_INTRINSICS)
    target_link_libraries(test_${str} bfvmm_intrinsics_static)
    target_link_libraries(test_${str} bfvmm_memory_manager_static)
    target_link_libraries(test_${str} test_catch)
    add_test(test_${str} test_${str})
    install(TARGETS test_${str} DESTINATION ${BUILD_SYSROOT_TEST}/bin/bfvmm)
endmacro(do_test)

do_test(acpi_intel_x64)
do_test(apic_intel_x64_lapic)
do_test(apic_intel_x64_xapic)
do_test(apic_intel_x64_x2apic)
do_test(cache_x64)
do_test(cpuid_x64)
do_test(crs_intel_x64)
do_test(debug_x64)
do_test(gdt_x64)
do_test(idt_x64)
do_test(mocks)
do_test(msrs_intel_x64)
do_test(msrs_x64)
do_test(pdpte_x64)
do_test(pm_x64)
do_test(portio_x64)
do_test(rdtsc_x64)
do_test(rflags_x64)
do_test(srs_x64)
do_test(tlb_x64)
do_test(vmcs_intel_x64_16bit_control_fields)
do_test(vmcs_intel_x64_16bit_guest_state_fields)
do_test(vmcs_intel_x64_16bit_host_state_fields)
do_test(vmcs_intel_x64_32bit_control_fields)
do_test(vmcs_intel_x64_32bit_guest_state_fields)
do_test(vmcs_intel_x64_32bit_host_state_fields)
do_test(vmcs_intel_x64_32bit_read_only_data_fields)
do_test(vmcs_intel_x64_64bit_control_fields)
do_test(vmcs_intel_x64_64bit_guest_state_fields)
do_test(vmcs_intel_x64_64bit_host_state_fields)
do_test(vmcs_intel_x64_64bit_read_only_data_fields)
do_test(vmcs_intel_x64_natural_width_control_fields)
do_test(vmcs_intel_x64_natural_width_guest_state_fields)
do_test(vmcs_intel_x64_natural_width_host_state_fields)
do_test(vmcs_intel_x64_natural_width_read_only_data_fields)
do_test(vmcs_intel_x64_check_controls)
do_test(vmcs_intel_x64_check_guest)
do_test(vmcs_intel_x64_check_host)
do_test(vmcs_intel_x64_debug)
do_test(vmcs_intel_x64_helpers)
do_test(vmx_intel_x64)
