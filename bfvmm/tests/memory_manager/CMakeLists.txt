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

do_test(test_memory_manager
    SOURCES test_memory_manager.cpp
    DEPENDS bfvmm_memory_manager
    DEFINES STATIC_MEMORY_MANAGER
)

do_test(test_buddy_allocator
    SOURCES test_buddy_allocator.cpp
    DEPENDS bfvmm_memory_manager
    DEFINES STATIC_MEMORY_MANAGER
)

if(NOT WIN32)
    do_test(test_object_allocator
        SOURCES test_object_allocator.cpp
        DEPENDS bfvmm_memory_manager
        DEFINES STATIC_MEMORY_MANAGER
    )
endif()

if(${BUILD_TARGET_ARCH} STREQUAL "x86_64")
    do_test(test_helpers
        SOURCES arch/x64/cr3/test_helpers.cpp
        DEPENDS bfvmm_memory_manager
        DEFINES STATIC_MEMORY_MANAGER
    )

    do_test(test_mmap
        SOURCES arch/x64/cr3/test_mmap.cpp
        DEPENDS bfvmm_memory_manager
        DEFINES STATIC_MEMORY_MANAGER
    )

    do_test(test_unique_map
        SOURCES arch/x64/test_unique_map.cpp
        DEPENDS bfvmm_memory_manager
        DEFINES STATIC_MEMORY_MANAGER
    )
elseif(${BUILD_TARGET_ARCH} STREQUAL "aarch64")
    message(WARNING "Unimplemented")
else()
    message(FATAL_ERROR "Unsupported archiecture")
endif()
