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

set(CATCH_INTERM_INSTALL_DIR ${BF_BUILD_DEPENDS_DIR}/catch/install)

list(APPEND CATCH_CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX=${CATCH_INTERM_INSTALL_DIR}
    -DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN_PATH_CATCH}
    -DCMAKE_INSTALL_MESSAGE=LAZY
)

ExternalProject_Add(
	catch
	GIT_REPOSITORY      https://github.com/Bareflank/Catch.git
	GIT_TAG             v1.2
	GIT_SHALLOW         1
	CMAKE_ARGS          ${CATCH_CMAKE_ARGS}
    PREFIX              ${BF_BUILD_DEPENDS_DIR}/catch
    SOURCE_DIR      	${BF_BUILD_DEPENDS_DIR}/catch/src
    BINARY_DIR          ${BF_BUILD_DEPENDS_DIR}/catch/build
    INSTALL_DIR         ${BF_BUILD_DEPENDS_DIR}/catch/install
    TMP_DIR             ${BF_BUILD_DEPENDS_DIR}/catch/tmp
    STAMP_DIR           ${BF_BUILD_DEPENDS_DIR}/catch/stamp
)

ExternalProject_Add_Step(
    catch
    catch_sysroot_install
    DEPENDEES install
    COMMAND	${CMAKE_COMMAND}
        -DGLOB_DIR=${CATCH_INTERM_INSTALL_DIR}
        -DGLOB_EXPR=*.hpp
        -DINSTALL_DIR=${BUILD_SYSROOT_TEST}
        -P ${BF_SCRIPTS_DIR}/cmake/copy_files_if_different.cmake
)
