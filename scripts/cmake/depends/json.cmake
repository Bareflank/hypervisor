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

if(ENABLE_BUILD_USERSPACE OR ENABLE_BUILD_TEST)
    message(STATUS "Including dependency: json")

    download_dependency(
        json
        URL         ${JSON_URL}
        URL_MD5     ${JSON_URL_MD5}
    )
endif()

if(ENABLE_BUILD_USERSPACE)
    add_dependency(
        json userspace
    )
endif()

if(ENABLE_BUILD_TEST)
    add_dependency(
        json test
    )
endif()
