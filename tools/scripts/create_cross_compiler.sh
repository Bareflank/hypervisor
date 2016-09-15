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
# GCC 5.1
# ------------------------------------------------------------------------------

if [[ -z "$CROSS_COMPILER" ]] || [[ $CROSS_COMPILER == "gcc_510" ]]; then

    export PREFIX="$HOME/compilers/gcc_510/"

    rm -Rf $PREFIX
    mkdir -p $PREFIX

    export PATH="$PREFIX/bin:$ORIGINAL_PATH"
    export BINUTILS_URL="http://ftp.gnu.org/gnu/binutils/binutils-2.25.1.tar.bz2"
    export GCC_URL="https://ftp.gnu.org/gnu/gcc/gcc-5.1.0/gcc-5.1.0.tar.bz2"
    export NASM_URL="http://www.nasm.us/pub/nasm/releasebuilds/2.12.01/nasm-2.12.01.tar.bz2"

    ./tools/scripts/fetch_binutils.sh
    ./tools/scripts/fetch_gcc.sh
    ./tools/scripts/fetch_nasm.sh

    ./tools/scripts/build_binutils.sh
    ./tools/scripts/build_gcc.sh
    ./tools/scripts/build_nasm.sh

fi

# ------------------------------------------------------------------------------
# GCC 5.2 / Clang 3.8
# ------------------------------------------------------------------------------

if [[ -z "$CROSS_COMPILER" ]] || [[ $CROSS_COMPILER == "gcc_520" ]]; then

    export PREFIX="$HOME/compilers/gcc_520/"
    export LLVM_RELEASE="release_38"

    rm -Rf $PREFIX
    mkdir -p $PREFIX

    export PATH="$PREFIX/bin:$ORIGINAL_PATH"
    export BINUTILS_URL="http://ftp.gnu.org/gnu/binutils/binutils-2.25.1.tar.bz2"
    export GCC_URL="https://ftp.gnu.org/gnu/gcc/gcc-5.2.0/gcc-5.2.0.tar.bz2"
    export NASM_URL="http://www.nasm.us/pub/nasm/releasebuilds/2.12.01/nasm-2.12.01.tar.bz2"

    ./tools/scripts/fetch_clang.sh
    ./tools/scripts/fetch_binutils.sh
    ./tools/scripts/fetch_gcc.sh
    ./tools/scripts/fetch_nasm.sh

    ./tools/scripts/build_clang.sh
    ./tools/scripts/build_binutils.sh
    ./tools/scripts/build_gcc.sh
    ./tools/scripts/build_nasm.sh
fi

# ------------------------------------------------------------------------------
# GCC 5.3
# ------------------------------------------------------------------------------

if [[ -z "$CROSS_COMPILER" ]] || [[ $CROSS_COMPILER == "gcc_530" ]]; then

    export PREFIX="$HOME/compilers/gcc_530/"

    rm -Rf $PREFIX
    mkdir -p $PREFIX

    export PATH="$PREFIX/bin:$ORIGINAL_PATH"
    export BINUTILS_URL="http://ftp.gnu.org/gnu/binutils/binutils-2.25.1.tar.bz2"
    export GCC_URL="https://ftp.gnu.org/gnu/gcc/gcc-5.3.0/gcc-5.3.0.tar.bz2"
    export NASM_URL="http://www.nasm.us/pub/nasm/releasebuilds/2.12.01/nasm-2.12.01.tar.bz2"

    ./tools/scripts/fetch_binutils.sh
    ./tools/scripts/fetch_gcc.sh
    ./tools/scripts/fetch_nasm.sh

    ./tools/scripts/build_binutils.sh
    ./tools/scripts/build_gcc.sh
    ./tools/scripts/build_nasm.sh

fi

# ------------------------------------------------------------------------------
# GCC 5.4
# ------------------------------------------------------------------------------

if [[ -z "$CROSS_COMPILER" ]] || [[ $CROSS_COMPILER == "gcc_540" ]]; then

    export PREFIX="$HOME/compilers/gcc_540/"

    rm -Rf $PREFIX
    mkdir -p $PREFIX

    export PATH="$PREFIX/bin:$ORIGINAL_PATH"
    export BINUTILS_URL="http://ftp.gnu.org/gnu/binutils/binutils-2.25.1.tar.bz2"
    export GCC_URL="https://ftp.gnu.org/gnu/gcc/gcc-5.4.0/gcc-5.4.0.tar.bz2"
    export NASM_URL="http://www.nasm.us/pub/nasm/releasebuilds/2.12.01/nasm-2.12.01.tar.bz2"

    ./tools/scripts/fetch_binutils.sh
    ./tools/scripts/fetch_gcc.sh
    ./tools/scripts/fetch_nasm.sh

    ./tools/scripts/build_binutils.sh
    ./tools/scripts/build_gcc.sh
    ./tools/scripts/build_nasm.sh

fi

# ------------------------------------------------------------------------------
# GCC 6.1
# ------------------------------------------------------------------------------

if [[ -z "$CROSS_COMPILER" ]] || [[ $CROSS_COMPILER == "gcc_610" ]]; then

    export PREFIX="$HOME/compilers/gcc_610/"

    rm -Rf $PREFIX
    mkdir -p $PREFIX

    export PATH="$PREFIX/bin:$ORIGINAL_PATH"
    export BINUTILS_URL="http://ftp.gnu.org/gnu/binutils/binutils-2.26.tar.bz2"
    export GCC_URL="https://ftp.gnu.org/gnu/gcc/gcc-6.1.0/gcc-6.1.0.tar.bz2"
    export NASM_URL="http://www.nasm.us/pub/nasm/releasebuilds/2.12.01/nasm-2.12.01.tar.bz2"

    ./tools/scripts/fetch_binutils.sh
    ./tools/scripts/fetch_gcc.sh
    ./tools/scripts/fetch_nasm.sh

    ./tools/scripts/build_binutils.sh
    ./tools/scripts/build_gcc.sh
    ./tools/scripts/build_nasm.sh

fi

# ------------------------------------------------------------------------------
# GCC 6.2 / Clang 3.9
# ------------------------------------------------------------------------------

if [[ -z "$CROSS_COMPILER" ]] || [[ $CROSS_COMPILER == "gcc_620" ]]; then

    export PREFIX="$HOME/compilers/gcc_620/"
    export LLVM_RELEASE="release_39"

    rm -Rf $PREFIX
    mkdir -p $PREFIX

    export PATH="$PREFIX/bin:$ORIGINAL_PATH"
    export BINUTILS_URL="http://ftp.gnu.org/gnu/binutils/binutils-2.27.tar.bz2"
    export GCC_URL="https://ftp.gnu.org/gnu/gcc/gcc-6.2.0/gcc-6.2.0.tar.bz2"
    export NASM_URL="http://www.nasm.us/pub/nasm/releasebuilds/2.12.02/nasm-2.12.02.tar.bz2"

    ./tools/scripts/fetch_clang.sh
    ./tools/scripts/fetch_binutils.sh
    ./tools/scripts/fetch_gcc.sh
    ./tools/scripts/fetch_nasm.sh

    ./tools/scripts/build_clang.sh
    ./tools/scripts/build_binutils.sh
    ./tools/scripts/build_gcc.sh
    ./tools/scripts/build_nasm.sh
fi

# ------------------------------------------------------------------------------
# Cleanup
# ------------------------------------------------------------------------------

rm -Rf /tmp/bareflank/
