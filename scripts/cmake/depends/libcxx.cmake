#
# Copyright (C) 2019 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

if(ENABLE_BUILD_VMM OR (ENABLE_BUILD_TEST AND NOT WIN32))
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
        -DLIBCXX_ENABLE_SHARED=OFF
        -DLIBCXX_ENABLE_STATIC=ON
        -DLIBCXX_INCLUDE_TESTS=OFF
        -DLIBCXX_ENABLE_ABI_LINKER_SCRIPT=OFF
        -DCMAKE_TOOLCHAIN_FILE=${VMM_TOOLCHAIN_PATH}
        -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS}
        -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
    )

    add_dependency(
        libcxx vmm
        CMAKE_ARGS  ${LIBCXX_CONFIGURE_FLAGS}
        DEPENDS     libcxxabi_${VMM_PREFIX}
    )
endif()
