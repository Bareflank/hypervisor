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
        gnuefi efi
        CONFIGURE_COMMAND   ${CMAKE_COMMAND} -E copy_directory ${CACHE_DIR}/gnuefi/ ${DEPENDS_DIR}/gnuefi/${EFI_PREFIX}/build
        BUILD_COMMAND       make
        COMMAND             make -C lib
        COMMAND             make -C gnuefi
        INSTALL_COMMAND     make INSTALLROOT=${PREFIXES_DIR}/ PREFIX=${EFI_PREFIX} install
        COMMAND             make INSTALLROOT=${PREFIXES_DIR}/ PREFIX=${EFI_PREFIX} -C lib install
        COMMAND             make INSTALLROOT=${PREFIXES_DIR}/ PREFIX=${EFI_PREFIX} -C gnuefi install
    )
endif()
