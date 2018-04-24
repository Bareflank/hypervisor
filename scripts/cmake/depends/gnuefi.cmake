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

if(ENABLE_BUILD_EFI AND NOT WIN32)
    message(STATUS "Including dependency: gnuefi")

    download_dependency(
        gnuefi
        URL         ${GNUEFI_URL}
        URL_MD5     ${GNUEFI_URL_MD5}
    )

    add_dependency(
        gnuefi userspace
        DEPENDS libcxx_${VMM_PREFIX}
        CONFIGURE_COMMAND   ${CMAKE_COMMAND} -E copy_directory ${CACHE_DIR}/gnuefi/ ${DEPENDS_DIR}/gnuefi/${USERSPACE_PREFIX}/build
        COMMAND ${CMAKE_COMMAND} -E copy "${PREFIXES_DIR}/${VMM_PREFIX}/include/stdint.h" "${PREFIXES_DIR}/${USERSPACE_PREFIX}/include/stdint.h"
        COMMAND ${CMAKE_COMMAND} -E copy "${PREFIXES_DIR}/${VMM_PREFIX}/include/c++/v1/stddef.h" "${PREFIXES_DIR}/${USERSPACE_PREFIX}/include/c++/v1/stddef.h"
        COMMAND ${CMAKE_COMMAND} -E copy "${PREFIXES_DIR}/${VMM_PREFIX}/include/machine/_default_types.h" "${PREFIXES_DIR}/${USERSPACE_PREFIX}/include/"
        BUILD_COMMAND       make
        COMMAND             make -C lib
        COMMAND             make -C gnuefi
        INSTALL_COMMAND     make INSTALLROOT=${PREFIXES_DIR}/ PREFIX=${USERSPACE_PREFIX} install
        COMMAND             make INSTALLROOT=${PREFIXES_DIR}/ PREFIX=${USERSPACE_PREFIX} -C lib install
        COMMAND             make INSTALLROOT=${PREFIXES_DIR}/ PREFIX=${USERSPACE_PREFIX} -C gnuefi install
    )

endif()
