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

# TODO: This file currently only builds binutils for whatever host architecture
# cmake is currently running on. Update to build against the
# ${BUILD_TARGET_ARCH} build configuration, or remote the need for building
# binutils from source at all.

set(BINUTILS_INTERM_INSTALL_DIR ${BF_BUILD_DEPENDS_DIR}/binutils/install)

list(APPEND BINUTILS_ARGS
    --prefix=${BINUTILS_INTERM_INSTALL_DIR}
    --target=${BUILD_TARGET_ARCH}-vmm-elf
    --disable-nls
    --disable-werror
    --with-sysroot
)

if(${BUILD_VERBOSE})
    set(LOG_BINUTILS_OUTPUT 0)
else()
    set(LOG_BINUTILS_OUTPUT 1)
endif()

ExternalProject_Add(
    binutils
    URL                 http://ftp.gnu.org/gnu/binutils/binutils-2.28.tar.gz
    URL_MD5             d5d270fd0b698ed59ca5ade8e1b5059c
    CONFIGURE_COMMAND   ${BF_BUILD_DEPENDS_DIR}/binutils/src/configure ${BINUTILS_ARGS}
    UPDATE_DISCONNECTED 0
    UPDATE_COMMAND      ""
    BUILD_COMMAND       make
    INSTALL_COMMAND     make install
    PREFIX              ${BF_BUILD_DEPENDS_DIR}/binutils
    SOURCE_DIR          ${BF_BUILD_DEPENDS_DIR}/binutils/src
    BINARY_DIR          ${BF_BUILD_DEPENDS_DIR}/binutils/build
    INSTALL_DIR         ${BF_BUILD_DEPENDS_DIR}/binutils/install
    TMP_DIR             ${BF_BUILD_DEPENDS_DIR}/binutils/tmp
    STAMP_DIR           ${BF_BUILD_DEPENDS_DIR}/binutils/stamp
    DOWNLOAD_DIR        ${BF_BUILD_DEPENDS_DIR}/binutils/download
    LOG_DOWNLOAD        ${LOG_BINUTILS_OUTPUT}
    LOG_CONFIGURE       ${LOG_BINUTILS_OUTPUT}
    LOG_BUILD           ${LOG_BINUTILS_OUTPUT}
    LOG_INSTALL         ${LOG_BINUTILS_OUTPUT}
)

ExternalProject_Add_Step(
    binutils
    sysroot_install
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${BINUTILS_INTERM_INSTALL_DIR}/bin ${BUILD_SYSROOT_VMM}/bin
    DEPENDEES install
)
