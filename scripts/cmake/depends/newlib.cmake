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

if(NOT EXISTS "${BUILD_SYSROOT_VMM}/lib/libc.a" OR NOT EXISTS "${BUILD_SYSROOT_VMM}/lib/libc.so")
    set(NEWLIB_DIR ${BF_BUILD_DEPENDS_DIR}/newlib/src)
    set(NEWLIB_BUILD_DIR ${BF_BUILD_DEPENDS_DIR}/newlib/build)
    set(NEWLIB_INTERM_INSTALL_DIR ${BF_BUILD_DEPENDS_DIR}/newlib/install)
    set(NEWLIB_TARGET "${BUILD_TARGET_ARCH}-vmm-elf")

    list(APPEND NEWLIB_C_FLAGS
        "-DNOSTDINC_C"
    )

    if(BUILD_TYPE STREQUAL "Release")
        list(APPEND NEWLIB_C_FLAGS
            "-O3"
            "-DNDEBUG"
        )
    endif()

    generate_flags(
        VMM
        ADD_C_FLAGS ${NEWLIB_C_FLAGS}
        C_FLAGS_OUT NEWLIB_C_FLAGS
        CXX_FLAGS_OUT NEWLIB_CXX_FLAGS
        VERBOSE OFF
    )

    list(APPEND NEWLIB_ARGS
        "--disable-libgloss"
        "--disable-multilib"
        "--disable-newlib-supplied-syscalls"
        "--enable-newlib-multithread"
        "--enable-newlib-iconv"
        "--prefix=${NEWLIB_INTERM_INSTALL_DIR}"
        "--target=${NEWLIB_TARGET}"
        "CC_FOR_TARGET=${TOOLCHAIN_NEWLIB_CC}"
        "CXX_FOR_TARGET=${TOOLCHAIN_NEWLIB_CC}"
        "AS_FOR_TARGET=${TOOLCHAIN_NEWLIB_AS}"
        "AR_FOR_TARGET=${TOOLCHAIN_NEWLIB_AR}"
        "RANLIB_FOR_TARGET=${TOOLCHAIN_NEWLIB_RANLIB}"
        "CFLAGS_FOR_TARGET=${NEWLIB_C_FLAGS}"
    )

    if(${BUILD_VERBOSE})
        set(LOG_NEWLIB_OUTPUT 0)
    else()
        set(LOG_NEWLIB_OUTPUT 1)
    endif()

    ExternalProject_Add(
        newlib
        GIT_REPOSITORY      https://github.com/Bareflank/newlib.git
        GIT_TAG             v1.2
        GIT_SHALLOW         1
        CONFIGURE_COMMAND   ${NEWLIB_DIR}/configure ${NEWLIB_ARGS}
        BUILD_COMMAND       make
        INSTALL_COMMAND		make install
        DEPENDS             bfsdk binutils
        PREFIX              ${BF_BUILD_DEPENDS_DIR}/newlib
        SOURCE_DIR          ${BF_BUILD_DEPENDS_DIR}/newlib/src
        BINARY_DIR          ${BF_BUILD_DEPENDS_DIR}/newlib/build
        INSTALL_DIR         ${BF_BUILD_DEPENDS_DIR}/newlib/install
        TMP_DIR             ${BF_BUILD_DEPENDS_DIR}/newlib/tmp
        STAMP_DIR           ${BF_BUILD_DEPENDS_DIR}/newlib/stamp
        LOG_DOWNLOAD        ${LOG_NEWLIB_OUTPUT}
        LOG_CONFIGURE       ${LOG_NEWLIB_OUTPUT}
        LOG_BUILD           ${LOG_NEWLIB_OUTPUT}
        LOG_INSTALL         ${LOG_NEWLIB_OUTPUT}
    )

    ExternalProject_Add_Step(
        newlib
        build_shared_lib
        COMMAND cd ${NEWLIB_BUILD_DIR}/${NEWLIB_TARGET}/newlib && ${TOOLCHAIN_NEWLIB_AR} x libc.a
        COMMAND cd ${NEWLIB_BUILD_DIR}/${NEWLIB_TARGET}/newlib && ${TOOLCHAIN_NEWLIB_CC} -shared *.o -o ${NEWLIB_INTERM_INSTALL_DIR}/${NEWLIB_TARGET}/lib/libc.so
        DEPENDEES install
        )

    ExternalProject_Add_Step(
        newlib
        newlib_headers_sysroot_install
        DEPENDEES install
        COMMAND	${CMAKE_COMMAND}
            -DGLOB_DIR=${NEWLIB_INTERM_INSTALL_DIR}/${NEWLIB_TARGET}
            -DGLOB_EXPR=*.h
            -DINSTALL_DIR=${BUILD_SYSROOT_VMM}
            -P ${BF_SCRIPTS_DIR}/cmake/copy_files_if_different.cmake
    )

    ExternalProject_Add_Step(
        newlib
        newlib_static_sysroot_install
        DEPENDEES install
        COMMAND	${CMAKE_COMMAND}
            -DGLOB_DIR=${NEWLIB_INTERM_INSTALL_DIR}/${NEWLIB_TARGET}
            -DGLOB_EXPR=*.a
            -DINSTALL_DIR=${BUILD_SYSROOT_VMM}
            -P ${BF_SCRIPTS_DIR}/cmake/copy_files_if_different.cmake
    )

    ExternalProject_Add_Step(
        newlib
        newlib_shared_sysroot_install
        DEPENDEES build_shared_lib
        COMMAND	${CMAKE_COMMAND}
            -DGLOB_DIR=${NEWLIB_INTERM_INSTALL_DIR}/${NEWLIB_TARGET}
            -DGLOB_EXPR=*.so
            -DINSTALL_DIR=${BUILD_SYSROOT_VMM}
            -P ${BF_SCRIPTS_DIR}/cmake/copy_files_if_different.cmake
    )
else()
    add_custom_target(newlib)
endif()
