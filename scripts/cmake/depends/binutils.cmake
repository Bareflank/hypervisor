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

if((ENABLE_BUILD_VMM OR ENABLE_BUILD_TEST) AND NOT WIN32 AND ENABLE_BUILD_BINUTILS)
    message(STATUS "Including dependency: binutils")

    download_dependency(
        binutils
        URL         ${BINUTILS_URL}
        URL_MD5     ${BINUTILS_URL_MD5}
    )

    list(APPEND BINUTILS_CONFIGURE_FLAGS
        --disable-nls
        --disable-werror
        --with-sysroot
        --prefix=${PREFIXES_DIR}
        --target=${VMM_PREFIX}
    )

    add_dependency(
        binutils vmm
        CONFIGURE_COMMAND   ${CACHE_DIR}/binutils/configure ${BINUTILS_CONFIGURE_FLAGS}
        BUILD_COMMAND       make -j${BUILD_TARGET_CORES}
        INSTALL_COMMAND     make install
    )

    add_dependency_step(
        binutils vmm
        COMMAND ${CMAKE_COMMAND} -E remove_directory ${VMM_PREFIX}/lib/ldscripts
        COMMAND ${CMAKE_COMMAND} -E remove_directory ${PREFIXES_DIR}/bin
        COMMAND ${CMAKE_COMMAND} -E remove_directory ${PREFIXES_DIR}/share
    )
else()
    add_custom_target(binutils_${VMM_PREFIX})
endif()
