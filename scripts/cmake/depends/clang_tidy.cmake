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

if(ENABLE_TIDY)
    if(NOT CLANG_TIDY_BIN)
        find_program(CLANG_TIDY_BIN clang-tidy-6.0)

        if(NOT CLANG_TIDY_BIN)
            message(STATUS "Including dependency: clang-tidy")
            message(STATUS "*** FATAL ERROR: Clang Tidy 6.0 was not found. To Fix:")
            message(STATUS "  - install clang-tidy-6.0 or")
            message(STATUS "  - ln -s /usr/bin/clang-tidy /usr/bin/clang-tidy-6.0")
            message(FATAL_ERROR "Unable to find: clang-tidy")
        endif()
    endif()
endif()
