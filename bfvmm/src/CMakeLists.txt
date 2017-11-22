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

add_subdirectory(debug_ring)
add_subdirectory(intrinsics)
add_subdirectory(memory_manager)
add_subdirectory(serial)
add_subdirectory(vmxon)
add_subdirectory(vmcs)
add_subdirectory(exit_handler)
add_subdirectory(vcpu)
add_subdirectory(vcpu_factory)
add_subdirectory(vcpu_manager)

if(NOT ${PROJECT_NAME} STREQUAL bfvmm_test)
    add_subdirectory(support)
    add_subdirectory(main)
endif()
