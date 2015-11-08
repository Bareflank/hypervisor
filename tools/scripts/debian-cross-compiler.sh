#!/bin/bash

if [ -z "$BINUTILS_PATH" ]; then
    export BINUTILS_PATH="http://ftp.gnu.org/gnu/binutils/binutils-2.25.1.tar.bz2"
fi

if [ -z "$GCC_PATH" ]; then
    export GCC_PATH="https://ftp.gnu.org/gnu/gcc/gcc-5.2.0/gcc-5.2.0.tar.bz2"
fi

if [ -n "${SILENCE+1}" ]; then
  exec 1>/dev/null
  exec 2>/dev/null
fi

export TMPDIR="$HOME/tmp-build-dir"
export PREFIX="$HOME/opt/cross"
export TARGET=x86_64-elf
export PATH="$PREFIX/bin:$PATH"

sudo apt-get install build-essential libgmp-dev libmpc-dev libmpfr-dev libisl-dev flex bison -y

rm -Rf $TMPDIR
mkdir -p $TMPDIR

pushd $TMPDIR

wget $BINUTILS_PATH
wget $GCC_PATH

tar xf binutils-*.tar.bz2
tar xf gcc-*.tar.bz2

mkdir build-binutils
mkdir build-gcc

pushd $TMPDIR/build-binutils
../binutils-*/configure --target=$TARGET --prefix="$PREFIX" --with-sysroot --disable-nls --disable-werror
make
make install
popd

pushd $TMPDIR/build-gcc
../gcc-*/configure --target=$TARGET --prefix="$PREFIX" --disable-nls --enable-languages=c,c++ --without-headers
make all-gcc
make all-target-libgcc
make install-gcc
make install-target-libgcc
popd

popd
rm -Rf $TMPDIR
