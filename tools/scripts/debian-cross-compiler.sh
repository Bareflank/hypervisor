#!/bin/bash

set -e

if [ -z "$BINUTILS_PATH" ]; then
    export BINUTILS_PATH="http://ftp.gnu.org/gnu/binutils/binutils-2.25.1.tar.bz2"
fi

if [ -z "$GCC_PATH" ]; then
    export GCC_PATH="https://ftp.gnu.org/gnu/gcc/gcc-5.2.0/gcc-5.2.0.tar.bz2"
fi

if [ -z "$GCC_PATCH" ]; then
    export GCC_PATCH="https://raw.githubusercontent.com/Bareflank/hypervisor/master/tools/patches/gcc-5.2.0_bareflank.patch"
fi

if [ -z "$NASM_PATH" ]; then
    export NASM_PATH="http://www.nasm.us/pub/nasm/releasebuilds/2.11.08/nasm-2.11.08.tar.gz"
fi

if [ -n "${SILENCE+1}" ]; then
  exec 1>/dev/null
  exec 2>/dev/null
fi

export TMPDIR="$HOME/tmp-build-dir"
export PREFIX="$HOME/opt/cross"
export TARGET=x86_64-elf
export PATH="$PREFIX/bin:$PATH"

sudo apt-get install build-essential libgmp-dev libmpc-dev libmpfr-dev libisl-dev flex bison nasm -y

rm -Rf $TMPDIR
mkdir -p $TMPDIR

pushd $TMPDIR
wget $BINUTILS_PATH
wget $GCC_PATH
wget $GCC_PATCH
wget $NASM_PATH

tar xvf binutils-*.tar.bz2
tar xvf gcc-*.tar.bz2
tar xvf nasm-*.tar.gz

mkdir build-binutils
mkdir build-gcc
popd

pushd $TMPDIR/gcc-*
patch -p1 < ../gcc-*_bareflank.patch
popd

pushd $TMPDIR/build-binutils
../binutils-*/configure --target=$TARGET --prefix="$PREFIX" --with-sysroot --disable-nls --disable-werror
make -j2
make install
popd

pushd $TMPDIR/build-gcc
../gcc-*/configure --target=$TARGET --prefix="$PREFIX" --disable-nls --enable-languages=c,c++ --without-headers
make -j2 all-gcc
make -j2 all-target-libgcc
make -j2 install-gcc
make -j2 install-target-libgcc
popd

pushd $TMPDIR/nasm-*
./configure --prefix="$PREFIX"
make -j2
make install
popd

rm -Rf $TMPDIR
