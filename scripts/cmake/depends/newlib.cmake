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

if((ENABLE_BUILD_VMM OR ENABLE_BUILD_TEST) AND NOT WIN32)
    message(STATUS "Including dependency: newlib")

    download_dependency(
        newlib
        URL         ${NEWLIB_URL}
        URL_MD5     ${NEWLIB_URL_MD5}
    )

    if(DEFINED ENV{CLANG_BIN})
        set(CC_FOR_TARGET $ENV{CLANG_BIN})
        set(CXX_FOR_TARGET $ENV{CLANG_BIN})
    else()
        set(CC_FOR_TARGET clang)
        set(CXX_FOR_TARGET clang)
    endif()

    set(AR_FOR_TARGET ar)
    set(AS_FOR_TARGET as)
    set(NM_FOR_TARGET nm)
    set(OBJCOPY_FOR_TARGET objcopy)
    set(OBJDUMP_FOR_TARGET objdump)
    set(RANLIB_FOR_TARGET ranlib)
    set(READELF_FOR_TARGET readelf)
    set(STRIP_FOR_TARGET strip)

    if(DEFINED ENV{LD_BIN})
        set(LD_FOR_TARGET $ENV{LD_BIN})
    else()
        set(LD_FOR_TARGET ${VMM_PREFIX_PATH}/bin/ld)
    endif()

    generate_flags(
        vmm
        NOWARNINGS
    )

    string(CONCAT LD_FLAGS
        "--sysroot=${CMAKE_INSTALL_PREFIX} "
        "-z max-page-size=4096 "
        "-z common-page-size=4096 "
        "-z relro "
        "-z now "
        "-nostdlib "
    )

    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -DNDEBUG")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -DNDEBUG")
    else()
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
    endif()

    list(APPEND NEWLIB_CONFIGURE_FLAGS
        --disable-libgloss
        --disable-multilib
        --disable-newlib-supplied-syscalls
        --enable-newlib-multithread
        --enable-newlib-iconv
        CFLAGS_FOR_TARGET=${CMAKE_C_FLAGS}
        CXXFLAGS_FOR_TARGET=${CMAKE_CXX_FLAGS}
        CC_FOR_TARGET=${CC_FOR_TARGET}
        CXX_FOR_TARGET=${CXX_FOR_TARGET}
        AR_FOR_TARGET=${AR_FOR_TARGET}
        AS_FOR_TARGET=${AS_FOR_TARGET}
        LD_FOR_TARGET=${LD_FOR_TARGET}
        NM_FOR_TARGET=${NM_FOR_TARGET}
        OBJCOPY_FOR_TARGET=${OBJCOPY_FOR_TARGET}
        OBJDUMP_FOR_TARGET=${OBJDUMP_FOR_TARGET}
        RANLIB_FOR_TARGET=${RANLIB_FOR_TARGET}
        READELF_FOR_TARGET=${READELF_FOR_TARGET}
        STRIP_FOR_TARGET=${STRIP_FOR_TARGET}
        --prefix=${PREFIXES_DIR}
        --target=${VMM_PREFIX}
    )

    add_dependency(
        newlib vmm
        CONFIGURE_COMMAND   ${CACHE_DIR}/newlib/configure ${NEWLIB_CONFIGURE_FLAGS}
        BUILD_COMMAND       make -j${BUILD_TARGET_CORES}
        INSTALL_COMMAND     make install
        DEPENDS             binutils_${VMM_PREFIX}
    )

    add_dependency_step(
        newlib vmm
        COMMAND eval "${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/tmp"
        COMMAND eval "${CMAKE_COMMAND} -E copy_if_different ${VMM_PREFIX_PATH}/lib/libc.a ${CMAKE_BINARY_DIR}/tmp"
        COMMAND eval "${CMAKE_COMMAND} -E chdir ${CMAKE_BINARY_DIR}/tmp ${AR_FOR_TARGET} x libc.a"
        COMMAND eval "${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/tmp"

        COMMAND eval "${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/tmp"
        COMMAND eval "${CMAKE_COMMAND} -E copy_if_different ${VMM_PREFIX_PATH}/lib/libm.a ${CMAKE_BINARY_DIR}/tmp"
        COMMAND eval "${CMAKE_COMMAND} -E chdir ${CMAKE_BINARY_DIR}/tmp ${AR_FOR_TARGET} x libm.a"
        COMMAND eval "${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/tmp"

        COMMAND eval "${CMAKE_COMMAND} -E remove_directory ${PREFIXES_DIR}/share"
    )
endif()
