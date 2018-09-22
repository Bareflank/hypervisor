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

unset(BFFLAGS_USERSPACE)
unset(BFFLAGS_USERSPACE_C)
unset(BFFLAGS_USERSPACE_CXX)
unset(BFFLAGS_USERSPACE_X86_64)
unset(BFFLAGS_USERSPACE_AARCH64)

list(APPEND BFFLAGS_USERSPACE
    -DGSL_THROW_ON_CONTRACT_VIOLATION
    -DNATIVE
    -D${OSTYPE}
    -D${ABITYPE}
)

if(NOT WIN32)
    list(APPEND BFFLAGS_USERSPACE
        -fpic
        -fstack-protector-strong
        -fvisibility=hidden
        -Wno-deprecated-declarations
    )

    list(APPEND BFFLAGS_USERSPACE_C
        -std=c11
    )

    list(APPEND BFFLAGS_USERSPACE_CXX
        -std=c++17
        -fvisibility-inlines-hidden
    )

    list(APPEND BFFLAGS_USERSPACE_X86_64
        -msse
        -msse2
        -msse3
    )
else()
    list(APPEND BFFLAGS_USERSPACE
        /EHsc
        /bigobj
        /WX
        /D_SCL_SECURE_NO_WARNINGS
        /D_CRT_SECURE_NO_WARNINGS
        /DNOMINMAX
    )

    list(APPEND BFFLAGS_USERSPACE_C
        /std:c++17
    )

    list(APPEND BFFLAGS_USERSPACE_CXX
        /std:c++17
    )
endif()
