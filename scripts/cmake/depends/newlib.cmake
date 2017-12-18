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

get_dependency_src_dir(newlib NEWLIB_SRC_DIR)
get_dependency_install_dir(newlib NEWLIB_INSTALL_DIR)

set(NEWLIB_TARGET "${BUILD_TARGET_ARCH}-vmm-elf")

list(APPEND NEWLIB_C_FLAGS
    "-DNOSTDINC_C"
)

if(BUILD_TYPE STREQUAL "Release")
    list(APPEND NEWLIB_C_FLAGS
        "-O3"
        "-DNDEBUG"
        "-no-integrated-as"
        "-fasm"
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
    "--prefix=${NEWLIB_INSTALL_DIR}"
    "--target=${NEWLIB_TARGET}"
    "CC_FOR_TARGET=${TOOLCHAIN_NEWLIB_CC}"
    "CXX_FOR_TARGET=${TOOLCHAIN_NEWLIB_CC}"
    "AS_FOR_TARGET=${TOOLCHAIN_NEWLIB_AS}"
    "AR_FOR_TARGET=${TOOLCHAIN_NEWLIB_AR}"
    "RANLIB_FOR_TARGET=${TOOLCHAIN_NEWLIB_RANLIB}"
    "CFLAGS_FOR_TARGET=${NEWLIB_C_FLAGS}"
)


add_dependency(
    newlib
    GIT_REPOSITORY      https://github.com/Bareflank/newlib.git
    GIT_TAG             v1.2
    GIT_SHALLOW         1
    CONFIGURE_COMMAND   ${NEWLIB_SRC_DIR}/configure ${NEWLIB_ARGS}
    BUILD_COMMAND       make
    INSTALL_COMMAND		make install
    DEPENDS             bfsdk binutils
)

ExternalProject_Add_Step(
    newlib
    build_shared_lib
    COMMAND ${CMAKE_COMMAND} -E make_directory ${NEWLIB_INSTALL_DIR}/tmp
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${NEWLIB_INSTALL_DIR}/${NEWLIB_TARGET}/lib/libc.a ${NEWLIB_INSTALL_DIR}/tmp
    COMMAND ${CMAKE_COMMAND} -E chdir ${NEWLIB_INSTALL_DIR}/tmp ${TOOLCHAIN_NEWLIB_AR} x libc.a
    COMMAND ${CMAKE_COMMAND} -E chdir ${NEWLIB_INSTALL_DIR}/tmp ${TOOLCHAIN_NEWLIB_CC} -shared -o libc.so *.o
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${NEWLIB_INSTALL_DIR}/tmp/libc.so ${NEWLIB_INSTALL_DIR}/${NEWLIB_TARGET}/lib
    DEPENDEES install
    COMMENT "Installing newlib shared library (libc.so) to ${NEWLIB_INSTALL_DIR}/${NEWLIB_TARGET}/lib"
)

install_dependency(
    newlib
    DESTINATIONS ${BUILD_SYSROOT_VMM}
    GLOB_DIR ${NEWLIB_INSTALL_DIR}/${NEWLIB_TARGET}
    GLOB_EXPRESSIONS *
    DEPENDEES build_shared_lib
)
