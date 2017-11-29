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

# libcxx and libcxxabi both depend on each other's source code to build, so the
# download step for both are declared seperately to avoid a circular dependency

ExternalProject_Add(
    libcxxabi_download
    GIT_REPOSITORY      https://github.com/Bareflank/libcxxabi.git
    GIT_TAG             v1.2
    GIT_SHALLOW         1
    PREFIX              ${BF_BUILD_DEPENDS_DIR}/libcxxabi
    SOURCE_DIR          ${BF_BUILD_DEPENDS_DIR}/libcxxabi/src
    BINARY_DIR          ${BF_BUILD_DEPENDS_DIR}/libcxxabi/build
    INSTALL_DIR         ${BF_BUILD_DEPENDS_DIR}/libcxxabi/install
    TMP_DIR             ${BF_BUILD_DEPENDS_DIR}/libcxxabi/tmp
    STAMP_DIR           ${BF_BUILD_DEPENDS_DIR}/libcxxabi/stamp
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
    DEPENDS bfsdk
)

ExternalProject_Add(
    libcxx_download
	GIT_REPOSITORY      https://github.com/Bareflank/libcxx.git
	GIT_TAG             v1.2
	GIT_SHALLOW         1
    PREFIX              ${BF_BUILD_DEPENDS_DIR}/libcxx
    SOURCE_DIR          ${BF_BUILD_DEPENDS_DIR}/libcxx/src
    BINARY_DIR          ${BF_BUILD_DEPENDS_DIR}/libcxx/build
    INSTALL_DIR         ${BF_BUILD_DEPENDS_DIR}/libcxx/install
    TMP_DIR             ${BF_BUILD_DEPENDS_DIR}/libcxx/tmp
    STAMP_DIR           ${BF_BUILD_DEPENDS_DIR}/libcxx/stamp
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
    DEPENDS bfsdk
)
