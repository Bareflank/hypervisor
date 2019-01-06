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

add_library(bfvmm_vcpu)

target_sources(bfvmm_vcpu PRIVATE vcpu.cpp)
target_link_libraries(bfvmm_vcpu PUBLIC ${PREFIX}::bfroot)
target_include_directories(bfvmm_vcpu PUBLIC
    $<${BUILD_INCLUDE}:${PROJECT_ROOT}/include>
    $<${BUILD_INCLUDE}:${PROJECT_ROOT}/../bfintrinsics/include>
    $<${BUILD_INCLUDE}:${PROJECT_ROOT}/../bfutil/include>
)

install(TARGETS bfvmm_vcpu DESTINATION lib EXPORT bfvmm-${PREFIX}-targets)

if(PREFIX STREQUAL vmm)
    install(DIRECTORY ../../include/vcpu/ DESTINATION include/bfvmm/vcpu)
endif()
