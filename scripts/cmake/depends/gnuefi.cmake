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

if(ENABLE_BUILD_EFI AND NOT WIN32)
    message(STATUS "Including dependency: gnuefi")

    download_dependency(
        gnuefi
        URL         ${GNUEFI_URL}
        URL_MD5     ${GNUEFI_URL_MD5}
    )

    add_dependency(
        gnuefi efi
        CONFIGURE_COMMAND   ${CMAKE_COMMAND} -E copy_directory ${CACHE_DIR}/gnuefi/ ${DEPENDS_DIR}/gnuefi/${EFI_PREFIX}/build
        BUILD_COMMAND       make
        COMMAND             make -C lib
        COMMAND             make -C gnuefi
        INSTALL_COMMAND     make INSTALLROOT=${PREFIXES_DIR}/ PREFIX=${EFI_PREFIX} install
        COMMAND             make INSTALLROOT=${PREFIXES_DIR}/ PREFIX=${EFI_PREFIX} -C lib install
        COMMAND             make INSTALLROOT=${PREFIXES_DIR}/ PREFIX=${EFI_PREFIX} -C gnuefi install
    )
endif()
