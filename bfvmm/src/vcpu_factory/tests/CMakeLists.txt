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
    target_compile_definitions(test_${str} PRIVATE STATIC_VCPU)
    target_link_libraries(test_${str} bfvmm_vcpu_factory_static)
    target_link_libraries(test_${str} bfvmm_vcpu_static)
    target_link_libraries(test_${str} bfvmm_vmxon_static)
    target_link_libraries(test_${str} bfvmm_exit_handler_static)
    target_link_libraries(test_${str} bfvmm_vmcs_static)
    target_link_libraries(test_${str} bfvmm_memory_manager_static)
    target_link_libraries(test_${str} bfvmm_intrinsics_static)
    target_link_libraries(test_${str} test_catch)
    add_test(test_${str} test_${str})
    install(TARGETS test_${str} DESTINATION ${BUILD_SYSROOT_TEST}/bin/bfvmm)
endmacro(do_test)

do_test(vcpu_factory_intel_x64)
