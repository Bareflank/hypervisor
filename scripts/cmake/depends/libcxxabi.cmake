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

generate_flags(
    VMM
    C_FLAGS_OUT LIBCXXABI_C_FLAGS
    CXX_FLAGS_OUT LIBCXXABI_CXX_FLAGS
    VERBOSE OFF
)

list(APPEND LIBCXXABI_CMAKE_ARGS
    -DLLVM_PATH=${BF_BUILD_DEPENDS_DIR}/llvm/src
	-DLLVM_ENABLE_LIBCXX=ON
    -DLIBCXXABI_LIBCXX_PATH=${BF_BUILD_DEPENDS_DIR}/libcxx/src
    -DLIBCXXABI_SYSROOT=${BUILD_SYSROOT_VMM}
    -DLIBCXXABI_HAS_PTHREAD_API=ON
    -DCMAKE_INSTALL_PREFIX=${BUILD_SYSROOT_VMM}
    -DCMAKE_BUILD_TYPE=${BUILD_TYPE}
    -DCMAKE_SYSTEM_NAME=${CMAKE_SYSTEM_NAME}
    -DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN_PATH_LIBCXXABI}
    -DCMAKE_C_FLAGS=${LIBCXXABI_C_FLAGS}
    -DCMAKE_CXX_FLAGS=${LIBCXXABI_CXX_FLAGS}
    -DBUILD_SYSROOT_VMM=${BUILD_SYSROOT_VMM}
    -DCMAKE_INSTALL_MESSAGE=LAZY
)

if(BUILD_VMM_SHARED)
    list(APPEND LIBCXXABI_CMAKE_ARGS -DLIBCXXABI_ENABLE_SHARED=ON)
endif()

if(BUILD_VMM_STATIC)
    list(APPEND LIBCXXABI_CMAKE_ARGS -DLIBCXXABI_ENABLE_STATIC=ON)
endif()

ExternalProject_Add(
    libcxxabi
    GIT_REPOSITORY      https://github.com/Bareflank/libcxxabi.git
    GIT_TAG             v1.2
    GIT_SHALLOW         1
    PREFIX              ${BF_BUILD_DEPENDS_DIR}/libcxxabi
    SOURCE_DIR          ${BF_BUILD_DEPENDS_DIR}/libcxxabi/src
    BINARY_DIR          ${BF_BUILD_DEPENDS_DIR}/libcxxabi/build
    INSTALL_DIR         ${BF_BUILD_DEPENDS_DIR}/libcxxabi/install
    TMP_DIR             ${BF_BUILD_DEPENDS_DIR}/libcxxabi/tmp
    STAMP_DIR           ${BF_BUILD_DEPENDS_DIR}/libcxxabi/stamp
	CMAKE_ARGS      	${LIBCXXABI_CMAKE_ARGS}
    UPDATE_DISCONNECTED 0
    UPDATE_COMMAND      ""
    DEPENDS libcxx_download libcxxabi_download llvm newlib bfsdk binutils
)
