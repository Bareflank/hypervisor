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

ExternalProject_Add(
	llvm
	GIT_REPOSITORY      https://github.com/Bareflank/llvm.git
	GIT_TAG             v1.2
	GIT_SHALLOW         1
    CONFIGURE_COMMAND   ""
    BUILD_COMMAND       ""
    INSTALL_COMMAND     ""
    PREFIX              ${BF_BUILD_DEPENDS_DIR}/llvm
    SOURCE_DIR          ${BF_BUILD_DEPENDS_DIR}/llvm/src
    BINARY_DIR          ${BF_BUILD_DEPENDS_DIR}/llvm/build
    TMP_DIR             ${BF_BUILD_DEPENDS_DIR}/llvm/tmp
    STAMP_DIR           ${BF_BUILD_DEPENDS_DIR}/llvm/stamp
    INSTALL_DIR         ${BF_BUILD_DEPENDS_DIR}/llvm/install
)
