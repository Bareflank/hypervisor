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
# ${BUILD_TARGET_ARCH} build configuration, or remove the need for building
# binutils from source at all.

get_dependency_src_dir(binutils BINUTILS_SRC_DIR)
get_dependency_install_dir(binutils BINUTILS_INSTALL_DIR)

list(APPEND BINUTILS_ARGS
    --prefix=${BINUTILS_INSTALL_DIR}
    --target=${BUILD_TARGET_ARCH}-vmm-elf
    --disable-nls
    --disable-werror
    --with-sysroot
)

add_dependency(
    binutils
    URL                 http://ftp.gnu.org/gnu/binutils/binutils-2.28.tar.gz
    URL_MD5             d5d270fd0b698ed59ca5ade8e1b5059c
    CONFIGURE_COMMAND   ${BINUTILS_SRC_DIR}/configure ${BINUTILS_ARGS}
    UPDATE_DISCONNECTED 0
    UPDATE_COMMAND      ""
    BUILD_COMMAND       make
    INSTALL_COMMAND     make install
)

install_dependency(
    binutils
    DESTINATIONS ${BUILD_SYSROOT_VMM}
    GLOB_EXPRESSIONS bin/*
)
