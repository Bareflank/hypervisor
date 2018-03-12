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

if((ENABLE_BUILD_VMM OR ENABLE_BUILD_TEST) AND NOT WIN32)
    message(STATUS "Including dependency: libcxxabi")

    download_dependency(
        libcxxabi
        URL          ${LIBCXXABI_URL}
        URL_MD5      ${LIBCXXABI_URL_MD5}
    )

    generate_flags(
        vmm
        NOWARNINGS
    )

    list(APPEND LIBCXXABI_CONFIGURE_FLAGS
        -DLLVM_PATH=${CACHE_DIR}/llvm
        -DLLVM_ENABLE_LIBCXX=ON
        -DLIBCXXABI_LIBCXX_PATH=${CACHE_DIR}/libcxx
        -DLIBCXXABI_SYSROOT=${VMM_PREFIX_PATH}
        -DLIBCXXABI_HAS_PTHREAD_API=ON
        -DCMAKE_TOOLCHAIN_FILE=${VMM_TOOLCHAIN_PATH}
        -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS}
        -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
    )

    add_dependency(
        libcxxabi vmm
        CMAKE_ARGS  ${LIBCXXABI_CONFIGURE_FLAGS}
        DEPENDS     llvm_${VMM_PREFIX}
        DEPENDS     newlib_${VMM_PREFIX}
        DEPENDS     bfdso_${VMM_PREFIX}
    )
endif()
