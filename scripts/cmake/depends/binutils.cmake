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
if((ENABLE_BUILD_VMM OR ENABLE_BUILD_TEST) AND NOT WIN32 AND ENABLE_BUILD_BINUTILS)
    message(STATUS "Including dependency: binutils")

    download_dependency(
        binutils
        URL         ${BINUTILS_URL}
        URL_MD5     ${BINUTILS_URL_MD5}
    )

    list(APPEND BINUTILS_CONFIGURE_FLAGS
        --disable-nls
        --disable-werror
        --with-sysroot
        --prefix=${PREFIXES_DIR}
        --target=${VMM_PREFIX}
    )

    add_dependency(
        binutils vmm
        CONFIGURE_COMMAND   ${CACHE_DIR}/binutils/configure ${BINUTILS_CONFIGURE_FLAGS}
        BUILD_COMMAND       make -j${BUILD_TARGET_CORES}
        INSTALL_COMMAND     make install
    )

    add_dependency_step(
        binutils vmm
        COMMAND ${CMAKE_COMMAND} -E remove_directory ${VMM_PREFIX}/lib/ldscripts
        COMMAND ${CMAKE_COMMAND} -E remove_directory ${PREFIXES_DIR}/bin
        COMMAND ${CMAKE_COMMAND} -E remove_directory ${PREFIXES_DIR}/share
    )
else()
    add_custom_target(binutils_${VMM_PREFIX})
endif()
