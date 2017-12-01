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

set(JSON_INTERM_INSTALL_DIR ${BF_BUILD_DEPENDS_DIR}/json/install)

list(APPEND JSON_CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX=${JSON_INTERM_INSTALL_DIR}
    -DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN_PATH_JSON}
    -DCMAKE_INSTALL_MESSAGE=LAZY
)

ExternalProject_Add(
    json
    GIT_REPOSITORY      https://github.com/Bareflank/json.git
    GIT_TAG             v1.2
    GIT_SHALLOW         1
    CMAKE_ARGS          ${JSON_CMAKE_ARGS}
    PREFIX              ${BF_BUILD_DEPENDS_DIR}/json
    SOURCE_DIR          ${BF_BUILD_DEPENDS_DIR}/json/src
    BINARY_DIR          ${BF_BUILD_DEPENDS_DIR}/json/build
    INSTALL_DIR         ${BF_BUILD_DEPENDS_DIR}/json/install
    TMP_DIR             ${BF_BUILD_DEPENDS_DIR}/json/tmp
    STAMP_DIR           ${BF_BUILD_DEPENDS_DIR}/json/stamp
)

ExternalProject_Add_Step(
    json
    json_os_sysroot_install
    DEPENDEES install
    COMMAND	${CMAKE_COMMAND}
        -DGLOB_DIR=${JSON_INTERM_INSTALL_DIR}
        -DGLOB_EXPR=*.hpp
        -DINSTALL_DIR=${BUILD_SYSROOT_OS}
        -P ${BF_SCRIPTS_DIR}/cmake/copy_files_if_different.cmake
)

ExternalProject_Add_Step(
    json
    json_vmm_sysroot_install
    DEPENDEES install
    COMMAND	${CMAKE_COMMAND}
        -DGLOB_DIR=${JSON_INTERM_INSTALL_DIR}
        -DGLOB_EXPR=*.hpp
        -DINSTALL_DIR=${BUILD_SYSROOT_VMM}
        -P ${BF_SCRIPTS_DIR}/cmake/copy_files_if_different.cmake
)
