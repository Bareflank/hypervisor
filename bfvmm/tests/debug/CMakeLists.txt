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

do_test(test_debug_ring
    SOURCES debug_ring/test_debug_ring.cpp
    DEPENDS bfvmm_debug
    DEFINES STATIC_DEBUG
    DEFINES STATIC_INTRINSICS
)

do_test(test_serial_ns16550a
    SOURCES serial/test_serial_ns16550a.cpp
    DEPENDS bfvmm_debug
    DEFINES STATIC_DEBUG
    DEFINES STATIC_INTRINSICS
)

# do_test(test_serial_port_pl011
#     SOURCES serial/test_serial_pl011.cpp
#     DEPENDS bfvmm_debug
#     DEFINES STATIC_DEBUG
#     DEFINES STATIC_INTRINSICS
# )
