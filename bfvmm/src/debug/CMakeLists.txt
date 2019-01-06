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

add_library(bfvmm_debug)

target_link_libraries(bfvmm_debug PUBLIC ${PREFIX}::bfvmm)
target_sources(bfvmm_debug PRIVATE
    debug_ring/debug_ring.cpp
    serial/serial_ns16550a.cpp
    $<$<STREQUAL:${BUILD_TARGET_ARCH},x86_64>:arch/x64/serial_ns16550a.cpp>
    $<$<STREQUAL:${BUILD_TARGET_ARCH},aarch64>:arch/aarch64/serial_ns16550a.cpp>
    $<$<NOT:$<BOOL:${ENABLE_MOCKING}>>:unistd.cpp>
)

install(TARGETS bfvmm_debug DESTINATION lib EXPORT bfvmm-${PREFIX}-targets)

if(PREFIX STREQUAL vmm)
    install(DIRECTORY ../../include/debug/ DESTINATION include/bfvmm/debug)
endif()
