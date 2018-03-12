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
    message(STATUS "Including dependency: libcxx")

    download_dependency(
        libcxx
        URL          ${LIBCXX_URL}
        URL_MD5      ${LIBCXX_URL_MD5}
    )

    generate_flags(
        vmm
        NOWARNINGS
        CXX_FLAGS -Wno-constant-conversion
    )

    list(APPEND LIBCXX_CONFIGURE_FLAGS
        -DLLVM_PATH=${CACHE_DIR}/llvm
        -DLIBCXX_CXX_ABI=libcxxabi
        -DLIBCXX_CXX_ABI_INCLUDE_PATHS=${CACHE_DIR}/libcxxabi/include
        -DLIBCXX_SYSROOT=${VMM_PREFIX_PATH}
        -DLIBCXX_HAS_PTHREAD_API=ON
        -DLIBCXX_ENABLE_FILESYSTEM=OFF
        -DLIBCXX_ENABLE_EXPERIMENTAL_LIBRARY=OFF
        -DLIBCXX_HAVE_CXX_ATOMICS_WITHOUT_LIB=ON
        -DCMAKE_TOOLCHAIN_FILE=${VMM_TOOLCHAIN_PATH}
        -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS}
        -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
    )

    add_dependency(
        libcxx vmm
        CMAKE_ARGS  ${LIBCXX_CONFIGURE_FLAGS}
        DEPENDS     libcxxabi_${VMM_PREFIX}
    )

    add_dependency_step(
        libcxx vmm
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${VMM_PREFIX_PATH}/lib/libc++.so.1.0 ${VMM_PREFIX_PATH}/lib/libc++.so
    )
endif()
