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

cmake_minimum_required(VERSION 3.6)
project(bfsysroot C CXX)

set(DISABLE_WARNINGS ON)
set(DISABLE_VISIBILITY_HIDDEN ON)

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Project.txt)

# ------------------------------------------------------------------------------
# Newlib
# ------------------------------------------------------------------------------

if(ENABLE_UNITTESTING)

    add_custom_target(newlib)

else()

    set(NEWLIB_CFLAGS
        "${CMAKE_C_FLAGS} -DNOSTDINC_C"
    )

    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        set(NEWLIB_CFLAGS
            "${CMAKE_C_FLAGS} -O3 -DNDEBUG"
        )
    endif()

    list(APPEND NEWLIB_ARGS
        "--prefix=${CMAKE_BINARY_DIR}/newlib/prefix"
        "--target=${BAREFLANK_TARGET}"
        "--disable-libgloss"
        "--disable-multilib"
        "--disable-newlib-supplied-syscalls"
        "--enable-newlib-multithread"
        "--enable-newlib-iconv"
        "CC_FOR_TARGET=${CMAKE_C_COMPILER}"
        "CXX_FOR_TARGET=${CMAKE_CXX_COMPILER}"
    )

    ExternalProject_Add(
        newlib
        PREFIX              ${CMAKE_BINARY_DIR}/newlib/prefix
        TMP_DIR             ${CMAKE_BINARY_DIR}/newlib/tmp
        STAMP_DIR           ${CMAKE_BINARY_DIR}/newlib/stamp
        SOURCE_DIR          ${BAREFLANK_BINARY_DIR}/external/newlib/src
        BINARY_DIR          ${CMAKE_BINARY_DIR}/newlib/build
        CONFIGURE_COMMAND   ${BAREFLANK_BINARY_DIR}/external/newlib/src/configure "${NEWLIB_ARGS}" CFLAGS_FOR_TARGET=${NEWLIB_CFLAGS}
        UPDATE_DISCONNECTED 0
        UPDATE_COMMAND      ""
        BUILD_COMMAND       make
        INSTALL_COMMAND     make install
        LOG_CONFIGURE       1
        LOG_BUILD           1
        LOG_INSTALL         1
    )

    ExternalProject_Add_Step(
        newlib
        prefix_install
        COMMAND             ${CMAKE_COMMAND} -E copy_directory ${CMAKE_BINARY_DIR}/newlib/prefix/${BAREFLANK_TARGET}/ ${CMAKE_INSTALL_PREFIX}/sysroots/${BAREFLANK_TARGET}/
        DEPENDEES           install
    )

    if(BUILD_SHARED_LIBS)
        ExternalProject_Add_Step(
            newlib
            link
            COMMAND             ${CMAKE_COMMAND} -E copy ${CMAKE_INSTALL_PREFIX}/sysroots/${BAREFLANK_TARGET}/lib/libc.a libc.a
            COMMAND             ${CMAKE_AR} x libc.a
            COMMAND             ${CMAKE_C_COMPILER} -shared *.o -o ${CMAKE_INSTALL_PREFIX}/sysroots/${BAREFLANK_TARGET}/lib/libc.so
            DEPENDEES           prefix_install
        )
    endif()

endif()

# ------------------------------------------------------------------------------
# Unwind
# ------------------------------------------------------------------------------

if(ENABLE_UNITTESTING)

    add_custom_target(bfunwind)

else()

    list(APPEND BFUNWIND_CMAKE_ARGS
        -DBAREFLANK_SOURCE_DIR=${BAREFLANK_SOURCE_DIR}
        -DBAREFLANK_BINARY_DIR=${BAREFLANK_BINARY_DIR}
        -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
        -DENABLE_COVERAGE=${ENABLE_COVERAGE}
        -DENABLE_DYNAMIC_ASAN=${ENABLE_DYNAMIC_ASAN}
        -DENABLE_DYNAMIC_USAN=${ENABLE_DYNAMIC_USAN}
        -DENABLE_TIDY=${ENABLE_TIDY}
        -DENABLE_ASTYLE=${ENABLE_ASTYLE}
        -DENABLE_UNITTESTING=${ENABLE_UNITTESTING}
        -DBUILD_SHARED_LIBS=${BUILD_SHARED_LIBS}
        -DBUILD_STATIC_LIBS=${BUILD_STATIC_LIBS}
    )

    ExternalProject_Add(
        bfunwind
        CMAKE_ARGS      ${BFUNWIND_CMAKE_ARGS}
        PREFIX          ${CMAKE_BINARY_DIR}/bfunwind/prefix
        TMP_DIR         ${CMAKE_BINARY_DIR}/bfunwind/tmp
        STAMP_DIR       ${CMAKE_BINARY_DIR}/bfunwind/stamp
        SOURCE_DIR      ${CMAKE_SOURCE_DIR}/bfunwind
        BINARY_DIR      ${CMAKE_BINARY_DIR}/bfunwind/build
        UPDATE_DISCONNECTED 0
        UPDATE_COMMAND      ""
        DEPENDS         newlib
    )

endif()

# ------------------------------------------------------------------------------
# Libcxxabi
# ------------------------------------------------------------------------------

if(ENABLE_UNITTESTING)

    add_custom_target(libcxxabi)

else()

    list(APPEND LIBCXXABI_CMAKE_ARGS
        -DLLVM_PATH=${BAREFLANK_BINARY_DIR}/external/llvm/src
        -DLLVM_ENABLE_LIBCXX=ON
        -DLIBCXXABI_LIBCXX_PATH=${BAREFLANK_BINARY_DIR}/external/libcxx/src
        -DLIBCXXABI_SYSROOT=${BAREFLANK_SYSROOT_PATH}
        -DLIBCXXABI_HAS_PTHREAD_API=ON
        -DCMAKE_INSTALL_PREFIX=${BAREFLANK_SYSROOT_PATH}
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        -DCMAKE_SYSTEM_NAME=${CMAKE_SYSTEM_NAME}
        -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
        -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
        -DCMAKE_AR=${CMAKE_AR}
        -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS}
        "-DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS} -DNOSTDINC_CXX"
    )

    if(BUILD_SHARED_LIBS)
        list(APPEND LIBCXXABI_CMAKE_ARGS -DLIBCXXABI_ENABLE_SHARED=ON -DLIBCXXABI_ENABLE_STATIC=OFF)
    endif()

    if(BUILD_STATIC_LIBS)
        list(APPEND LIBCXXABI_CMAKE_ARGS -DLIBCXXABI_ENABLE_STATIC=ON -DLIBCXXABI_ENABLE_SHARED=OFF)
    endif()

    ExternalProject_Add(
        libcxxabi
        CMAKE_ARGS      ${LIBCXXABI_CMAKE_ARGS}
        PREFIX          ${CMAKE_BINARY_DIR}/libcxxabi/prefix
        TMP_DIR         ${CMAKE_BINARY_DIR}/libcxxabi/tmp
        STAMP_DIR       ${CMAKE_BINARY_DIR}/libcxxabi/stamp
        SOURCE_DIR      ${BAREFLANK_BINARY_DIR}/external/libcxxabi/src
        BINARY_DIR      ${CMAKE_BINARY_DIR}/libcxxabi/build
        UPDATE_DISCONNECTED 0
        UPDATE_COMMAND      ""
        DEPENDS         bfunwind
    )

endif()

# ------------------------------------------------------------------------------
# Libcxx
# ------------------------------------------------------------------------------

if(ENABLE_UNITTESTING)

    add_custom_target(libcxx)

else()

    list(APPEND LIBCXX_CMAKE_ARGS
        -DLLVM_PATH=${BAREFLANK_BINARY_DIR}/external/llvm/src
        -DLIBCXX_CXX_ABI=libcxxabi
        -DLIBCXX_CXX_ABI_INCLUDE_PATHS=${BAREFLANK_BINARY_DIR}/external/libcxxabi/src/include/
        -DLIBCXX_SYSROOT=${BAREFLANK_SYSROOT_PATH}
        -DLIBCXX_HAS_PTHREAD_API=ON
        -DLIBCXX_ENABLE_EXPERIMENTAL_LIBRARY=OFF
        -DCMAKE_INSTALL_PREFIX=${BAREFLANK_SYSROOT_PATH}
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        -DCMAKE_SYSTEM_NAME=${CMAKE_SYSTEM_NAME}
        -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
        -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
        -DCMAKE_AR=${CMAKE_AR}
        -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS}
        "-DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS} -DNOSTDINC_CXX"
    )

    if(BUILD_SHARED_LIBS)
        list(APPEND LIBCXX_CMAKE_ARGS -DLIBCXX_ENABLE_SHARED=ON -DLIBCXX_ENABLE_STATIC=OFF)
    endif()

    if(BUILD_STATIC_LIBS)
        list(APPEND LIBCXX_CMAKE_ARGS -DLIBCXX_ENABLE_STATIC=ON -DLIBCXX_ENABLE_SHARED=OFF)
    endif()

    ExternalProject_Add(
        libcxx
        CMAKE_ARGS      ${LIBCXX_CMAKE_ARGS}
        PREFIX          ${CMAKE_BINARY_DIR}/libcxx/prefix
        TMP_DIR         ${CMAKE_BINARY_DIR}/libcxx/tmp
        STAMP_DIR       ${CMAKE_BINARY_DIR}/libcxx/stamp
        SOURCE_DIR      ${BAREFLANK_BINARY_DIR}/external/libcxx/src
        BINARY_DIR      ${CMAKE_BINARY_DIR}/libcxx/build
        UPDATE_DISCONNECTED 0
        UPDATE_COMMAND      ""
        DEPENDS         bfunwind libcxxabi
    )

endif()

# ------------------------------------------------------------------------------
# Support
# ------------------------------------------------------------------------------

list(APPEND BFSUPPORT_CMAKE_ARGS
    -DBAREFLANK_SOURCE_DIR=${BAREFLANK_SOURCE_DIR}
    -DBAREFLANK_BINARY_DIR=${BAREFLANK_BINARY_DIR}
    -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
    -DENABLE_COVERAGE=${ENABLE_COVERAGE}
    -DENABLE_DYNAMIC_ASAN=${ENABLE_DYNAMIC_ASAN}
    -DENABLE_DYNAMIC_USAN=${ENABLE_DYNAMIC_USAN}
    -DENABLE_TIDY=${ENABLE_TIDY}
    -DENABLE_ASTYLE=${ENABLE_ASTYLE}
    -DENABLE_UNITTESTING=${ENABLE_UNITTESTING}
    -DBUILD_SHARED_LIBS=${BUILD_SHARED_LIBS}
    -DBUILD_STATIC_LIBS=${BUILD_STATIC_LIBS}
)

ExternalProject_Add(
    bfsupport
    CMAKE_ARGS      ${BFSUPPORT_CMAKE_ARGS}
    PREFIX          ${CMAKE_BINARY_DIR}/bfsupport/prefix
    TMP_DIR         ${CMAKE_BINARY_DIR}/bfsupport/tmp
    STAMP_DIR       ${CMAKE_BINARY_DIR}/bfsupport/stamp
    SOURCE_DIR      ${CMAKE_SOURCE_DIR}/bfsupport
    BINARY_DIR      ${CMAKE_BINARY_DIR}/bfsupport/build
    UPDATE_DISCONNECTED 0
    UPDATE_COMMAND      ""
    DEPENDS         newlib libcxxabi libcxx
)

# ------------------------------------------------------------------------------
# Clean
# ------------------------------------------------------------------------------

if(ENABLE_UNITTESTING)

    add_custom_target(distclean
        COMMAND ${CMAKE_COMMAND} --build . --target clean
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfunwind/build --target clean
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsupport/build --target clean
    )

else()

    add_custom_target(distclean
        COMMAND ${CMAKE_COMMAND} --build . --target clean
        COMMAND make -C ${CMAKE_BINARY_DIR}/newlib/build clean > /dev/null 2>&1
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfunwind/build --target clean
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/libcxxabi/build --target clean
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/libcxx/build --target clean
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsupport/build --target clean
    )

endif()

# ------------------------------------------------------------------------------
# Test
# ------------------------------------------------------------------------------

if(ENABLE_UNITTESTING)

    if(POLICY CMP0037)
        cmake_policy(SET CMP0037 OLD)
    endif()

    add_custom_target(test
        COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_BINARY_DIR}/bfsupport/build ctest
    )

endif()

# # ------------------------------------------------------------------------------
# # Tidy
# # ------------------------------------------------------------------------------
#
# if(ENABLE_TIDY)
#
#     add_custom_target(tidy
#         COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfunwind/build --target tidy
#         COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsupport/build --target tidy
#     )
#
#     add_custom_target(tidy-all
#         COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfunwind/build --target tidy-all
#         COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsupport/build --target tidy-all
#     )
#
# endif()
#
# # ------------------------------------------------------------------------------
# # Astyle
# # ------------------------------------------------------------------------------
#
# if(ENABLE_ASTYLE)
#
#     add_custom_target(format
#         COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfunwind/build --target format
#         COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsupport/build --target format
#     )
#
#     add_custom_target(format-all
#         COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfunwind/build --target format-all
#         COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsupport/build --target format-all
#     )
#
# endif()
