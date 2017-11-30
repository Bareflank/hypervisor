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

set(HIPPOMOCKS_INTERM_INSTALL_DIR ${BF_BUILD_DEPENDS_DIR}/hippomocks/install)

list(APPEND HIPPOMOCKS_CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX=${HIPPOMOCKS_INTERM_INSTALL_DIR}
    -DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN_PATH_HIPPOMOCKS}
    -DCMAKE_INSTALL_MESSAGE=LAZY
)

ExternalProject_Add(
	hippomocks
	GIT_REPOSITORY      https://github.com/Bareflank/hippomocks.git
	GIT_TAG             v1.2
	GIT_SHALLOW         1
	CMAKE_ARGS          ${HIPPOMOCKS_CMAKE_ARGS}
    PREFIX              ${BF_BUILD_DEPENDS_DIR}/hippomocks
    SOURCE_DIR          ${BF_BUILD_DEPENDS_DIR}/hippomocks/src
    BINARY_DIR          ${BF_BUILD_DEPENDS_DIR}/hippomocks/build
    INSTALL_DIR         ${BF_BUILD_DEPENDS_DIR}/hippomocks/install
    TMP_DIR             ${BF_BUILD_DEPENDS_DIR}/hippomocks/tmp
    STAMP_DIR           ${BF_BUILD_DEPENDS_DIR}/hippomocks/stamp
)

set(HIPPOMOCKS_COPY_CMD "COMMAND ${CMAKE_COMMAND} -E copy_if_different")

ExternalProject_Add_Step(
    hippomocks
    hippomocks_os_sysroot_install
    DEPENDEES install
    COMMAND	${CMAKE_COMMAND}
        -DGLOB_DIR=${HIPPOMOCKS_INTERM_INSTALL_DIR}
        -DGLOB_EXPR=include/*
        -DINSTALL_DIR=${BUILD_SYSROOT_TEST}
        -P ${BF_SCRIPTS_DIR}/cmake/copy_files_if_different.cmake
)
