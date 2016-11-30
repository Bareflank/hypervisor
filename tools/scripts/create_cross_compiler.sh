#!/bin/bash -e
#
# Bareflank Hypervisor
#
# Copyright (C) 2015 Assured Information Security, Inc.
# Author: Rian Quinn        <quinnr@ainfosec.com>
# Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

# ------------------------------------------------------------------------------
# Setup
# ------------------------------------------------------------------------------

if [[ -f /.dockerenv ]]; then
    HOME=/tmp
fi

ORIGINAL_PATH=$PATH

rm -Rf /tmp/bareflank/
rm -Rf "$HOME/compilers"

mkdir -p /tmp/bareflank/

# ------------------------------------------------------------------------------
# Scripts
# ------------------------------------------------------------------------------

if [[ -z "$CUSTOM_FETCH_BINUTILS" ]]; then
    fetch_binutils=./tools/scripts/fetch_binutils.sh
else
    fetch_binutils=$CUSTOM_FETCH_BINUTILS
fi

if [[ -z "$CUSTOM_FETCH_GCC" ]]; then
    fetch_gcc=./tools/scripts/fetch_gcc.sh
else
    fetch_gcc=$CUSTOM_FETCH_GCC
fi

if [[ -z "$CUSTOM_FETCH_NASM" ]]; then
    fetch_nasm=./tools/scripts/fetch_nasm.sh
else
    fetch_nasm=$CUSTOM_FETCH_NASM
fi

if [[ -z "$CUSTOM_FETCH_CLANG" ]]; then
    fetch_clang=./tools/scripts/fetch_clang.sh
else
    fetch_clang=$CUSTOM_FETCH_CLANG
fi

if [[ -z "$CUSTOM_BUILD_BINUTILS" ]]; then
    build_binutils=./tools/scripts/build_binutils.sh
else
    build_binutils=$CUSTOM_BUILD_BINUTILS
fi

if [[ -z "$CUSTOM_BUILD_GCC" ]]; then
    build_gcc=./tools/scripts/build_gcc.sh
else
    build_gcc=$CUSTOM_BUILD_GCC
fi

if [[ -z "$CUSTOM_BUILD_NASM" ]]; then
    build_nasm=./tools/scripts/build_nasm.sh
else
    build_nasm=$CUSTOM_BUILD_NASM
fi

if [[ -z "$CUSTOM_BUILD_CLANG" ]]; then
    build_clang=./tools/scripts/build_clang.sh
else
    build_clang=$CUSTOM_BUILD_CLANG
fi

# ------------------------------------------------------------------------------
# GCC 6.1
# ------------------------------------------------------------------------------

if [[ -z "$CROSS_COMPILER" ]] || [[ $CROSS_COMPILER == *"gcc_610"* ]]; then

    export PREFIX="$HOME/compilers/gcc_610/"

    rm -Rf $PREFIX
    mkdir -p $PREFIX

    export PATH="$PREFIX/bin:$ORIGINAL_PATH"
    export BINUTILS_URL="http://ftp.gnu.org/gnu/binutils/binutils-2.26.tar.bz2"
    export GCC_URL="https://ftp.gnu.org/gnu/gcc/gcc-6.1.0/gcc-6.1.0.tar.bz2"
    export NASM_URL="http://www.nasm.us/pub/nasm/releasebuilds/2.12.01/nasm-2.12.01.tar.bz2"

    eval $fetch_binutils
    eval $fetch_gcc
    eval $fetch_nasm

    eval $build_binutils
    eval $build_gcc
    eval $build_nasm

fi

# ------------------------------------------------------------------------------
# GCC 6.2
# ------------------------------------------------------------------------------

if [[ -z "$CROSS_COMPILER" ]] || [[ $CROSS_COMPILER == *"gcc_620"* ]]; then

    export PREFIX="$HOME/compilers/gcc_620/"

    rm -Rf $PREFIX
    mkdir -p $PREFIX

    export PATH="$PREFIX/bin:$ORIGINAL_PATH"
    export BINUTILS_URL="http://ftp.gnu.org/gnu/binutils/binutils-2.27.tar.bz2"
    export GCC_URL="https://ftp.gnu.org/gnu/gcc/gcc-6.2.0/gcc-6.2.0.tar.bz2"
    export NASM_URL="http://www.nasm.us/pub/nasm/releasebuilds/2.12.02/nasm-2.12.02.tar.bz2"

    eval $fetch_binutils
    eval $fetch_gcc
    eval $fetch_nasm

    eval $build_binutils
    eval $build_gcc
    eval $build_nasm
fi

# ------------------------------------------------------------------------------
# Clang 3.8
# ------------------------------------------------------------------------------

if [[ -z "$CROSS_COMPILER" ]] || [[ $CROSS_COMPILER == *"clang_38"* ]]; then

    export PREFIX="$HOME/compilers/clang_38/"

    rm -Rf $PREFIX
    mkdir -p $PREFIX

    export PATH="$PREFIX/bin:$ORIGINAL_PATH"
    export BINUTILS_URL="http://ftp.gnu.org/gnu/binutils/binutils-2.27.tar.bz2"
    export LLVM_RELEASE="release_38"
    export NASM_URL="http://www.nasm.us/pub/nasm/releasebuilds/2.12.02/nasm-2.12.02.tar.bz2"

    eval $fetch_binutils
    eval $fetch_clang
    eval $fetch_nasm

    eval $build_binutils
    eval $build_clang
    eval $build_nasm
fi

# ------------------------------------------------------------------------------
# Clang 3.9
# ------------------------------------------------------------------------------

if [[ -z "$CROSS_COMPILER" ]] || [[ $CROSS_COMPILER == *"clang_39"* ]]; then

    export PREFIX="$HOME/compilers/clang_39/"

    rm -Rf $PREFIX
    mkdir -p $PREFIX

    export PATH="$PREFIX/bin:$ORIGINAL_PATH"
    export BINUTILS_URL="http://ftp.gnu.org/gnu/binutils/binutils-2.27.tar.bz2"
    export LLVM_RELEASE="release_39"
    export NASM_URL="http://www.nasm.us/pub/nasm/releasebuilds/2.12.02/nasm-2.12.02.tar.bz2"

    eval $fetch_binutils
    eval $fetch_clang
    eval $fetch_nasm

    eval $build_binutils
    eval $build_clang
    eval $build_nasm
fi

# ------------------------------------------------------------------------------
# Cleanup
# ------------------------------------------------------------------------------

rm -Rf /tmp/bareflank/
