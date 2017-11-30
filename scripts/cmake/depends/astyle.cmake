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

set(ASTYLE_INTERM_INSTALL_DIR ${BF_BUILD_DEPENDS_DIR}/astyle/install)

list(APPEND ASTYLE_CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX=${ASTYLE_INTERM_INSTALL_DIR}
	-DCMAKE_BUILD_TYPE=${BUILD_TYPE}
    -DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN_PATH_ASTYLE}
    -DCMAKE_INSTALL_MESSAGE=LAZY
)

ExternalProject_Add(
    astyle
	GIT_REPOSITORY      https://github.com/Bareflank/astyle.git
	GIT_TAG             v1.2
	GIT_SHALLOW         1
	CMAKE_ARGS          ${ASTYLE_CMAKE_ARGS}
    PREFIX              ${BF_BUILD_DEPENDS_DIR}/astyle
    SOURCE_DIR          ${BF_BUILD_DEPENDS_DIR}/astyle/src
    BINARY_DIR          ${BF_BUILD_DEPENDS_DIR}/astyle/build
    INSTALL_DIR         ${BF_BUILD_DEPENDS_DIR}/astyle/install
    TMP_DIR             ${BF_BUILD_DEPENDS_DIR}/astyle/tmp
    STAMP_DIR           ${BF_BUILD_DEPENDS_DIR}/astyle/stamp
    DEPENDS             bfsdk
)
