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

get_dependency_src_dir(libcxx LIBCXX_SRC_DIR)
get_dependency_src_dir(libcxxabi LIBCXXABI_SRC_DIR)
get_dependency_src_dir(llvm LLVM_SRC_DIR)
get_dependency_install_dir(libcxx LIBCXX_INSTALL_DIR)
get_dependency_install_dir(libcxxabi LIBCXXABI_INSTALL_DIR)

add_dependency(
    libcxxabi
    GIT_REPOSITORY  https://github.com/Bareflank/libcxxabi.git
    GIT_TAG         v1.2
    GIT_SHALLOW     1
    DEPENDS         llvm newlib bfsdk binutils
    CMAKE_ARGS
        -DLLVM_PATH=${LLVM_SRC_DIR}
        -DLLVM_ENABLE_LIBCXX=ON
        -DLIBCXXABI_LIBCXX_PATH=${LIBCXX_SRC_DIR}
        -DLIBCXXABI_SYSROOT=${BUILD_SYSROOT_VMM}
        -DLIBCXXABI_HAS_PTHREAD_API=ON
        -DCMAKE_INSTALL_PREFIX=${LIBCXXABI_INSTALL_DIR}
        -DCMAKE_BUILD_TYPE=${BUILD_TYPE}
        -DCMAKE_SYSTEM_NAME=${CMAKE_SYSTEM_NAME}
        -DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN_PATH_LIBCXXABI}
        -DCMAKE_C_FLAGS=${LIBCXX_C_FLAGS}
        -DCMAKE_CXX_FLAGS=${LIBCXX_CXX_FLAGS}
        -DBUILD_SYSROOT_VMM=${BUILD_SYSROOT_VMM}
        -DLIBCXX_ENABLE_SHARED=ON
        -DLIBCXX_ENABLE_STATIC=ON
)

add_dependency(
    libcxx
    GIT_REPOSITORY  https://github.com/Bareflank/libcxx.git
    GIT_TAG         v1.2
    GIT_SHALLOW     1
    DEPENDS         llvm newlib bfsdk binutils
    CMAKE_ARGS
        -DLLVM_PATH=${LLVM_SRC_DIR}
        -DLIBCXX_CXX_ABI=libcxxabi
        -DLIBCXX_CXX_ABI_INCLUDE_PATHS=${LIBCXXABI_SRC_DIR}/include/
        -DLIBCXX_SYSROOT=${BUILD_SYSROOT_VMM}
        -DLIBCXX_HAS_PTHREAD_API=ON
        -DLIBCXX_ENABLE_EXPERIMENTAL_LIBRARY=OFF
        -DCMAKE_INSTALL_PREFIX=${LIBCXX_INSTALL_DIR}
        -DCMAKE_SYSTEM_NAME=${CMAKE_SYSTEM_NAME}
        -DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN_PATH_LIBCXX}
        -DCMAKE_C_FLAGS=${LIBCXX_C_FLAGS}
        -DCMAKE_CXX_FLAGS=${LIBCXX_CXX_FLAGS}
        -DBUILD_SYSROOT_VMM=${BUILD_SYSROOT_VMM}
        -DLIBCXX_ENABLE_SHARED=ON
        -DLIBCXX_ENABLE_STATIC=ON
)

install_dependency(
    libcxxabi
    DESTINATIONS ${BUILD_SYSROOT_VMM}
    GLOB_EXPRESSIONS *
)

install_dependency(
    libcxx
    DESTINATIONS ${BUILD_SYSROOT_VMM}
    GLOB_EXPRESSIONS *
)

# libcxx and libcxxabi both depend on each other's source code to build, so
# setup inter-project step dependencies to make sure that they build in the
# right order.
ExternalProject_Add_StepTargets(libcxx download)
ExternalProject_Add_StepTargets(libcxxabi download)

ExternalProject_Add_StepDependencies(
    libcxx configure
    libcxx-download
    libcxxabi-download
)

ExternalProject_Add_StepDependencies(
    libcxx build
    libcxxabi
)

ExternalProject_Add_StepDependencies(
    libcxxabi configure
    libcxx-download
    libcxxabi-download
)
