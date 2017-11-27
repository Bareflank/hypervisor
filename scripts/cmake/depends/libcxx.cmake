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
    C_FLAGS_OUT LIBCXX_C_FLAGS
    CXX_FLAGS_OUT LIBCXX_CXX_FLAGS
    VERBOSE OFF
)

list(APPEND LIBCXX_CMAKE_ARGS
    -DLLVM_PATH=${BF_BUILD_DEPENDS_DIR}/llvm/src
    -DLIBCXX_CXX_ABI=libcxxabi
    -DLIBCXX_CXX_ABI_INCLUDE_PATHS=${BF_BUILD_DEPENDS_DIR}/libcxxabi/src/include/
    -DLIBCXX_SYSROOT=${BUILD_SYSROOT_VMM}
	-DLIBCXX_HAS_PTHREAD_API=ON
	-DLIBCXX_ENABLE_EXPERIMENTAL_LIBRARY=OFF
    -DCMAKE_INSTALL_PREFIX=${BUILD_SYSROOT_VMM}
	-DCMAKE_SYSTEM_NAME=${CMAKE_SYSTEM_NAME}
    -DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN_PATH_LIBCXX}
	-DCMAKE_C_FLAGS=${LIBCXX_C_FLAGS}
	-DCMAKE_CXX_FLAGS=${LIBCXX_CXX_FLAGS}
    -DBUILD_SYSROOT_VMM=${BUILD_SYSROOT_VMM}
    -DCMAKE_INSTALL_MESSAGE=LAZY
)

if(BUILD_VMM_SHARED)
    list(APPEND LIBCXX_CMAKE_ARGS -DLIBCXX_ENABLE_SHARED=ON)
endif()

if(BUILD_VMM_STATIC)
    list(APPEND LIBCXX_CMAKE_ARGS -DLIBCXX_ENABLE_STATIC=ON)
endif()

ExternalProject_Add(
    libcxx
	GIT_REPOSITORY      https://github.com/Bareflank/libcxx.git
	GIT_TAG             v1.2
	GIT_SHALLOW         1
    UPDATE_DISCONNECTED 0
    UPDATE_COMMAND      ""
    PREFIX              ${BF_BUILD_DEPENDS_DIR}/libcxx
    SOURCE_DIR          ${BF_BUILD_DEPENDS_DIR}/libcxx/src
    BINARY_DIR          ${BF_BUILD_DEPENDS_DIR}/libcxx/build
    INSTALL_DIR         ${BF_BUILD_DEPENDS_DIR}/libcxx/install
    TMP_DIR             ${BF_BUILD_DEPENDS_DIR}/libcxx/tmp
    STAMP_DIR           ${BF_BUILD_DEPENDS_DIR}/libcxx/stamp
	CMAKE_ARGS      	${LIBCXX_CMAKE_ARGS}
    DEPENDS libcxx_download libcxxabi_download llvm newlib libcxxabi bfsdk binutils
)
