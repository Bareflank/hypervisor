#!/bin/bash

export PREFIX="$HOME/opt/cross-compiler"
export GCC_TARGET=x86_64-elf
export BINUTILS_TARGET=x86_64-elf
export PATH="$PREFIX/bin:$PATH"

apt-get install build-essentials libmpc-dev libisl-dev

mkdir -p $PREFIX

pushd ~/Downloads
#wget https://ftp.gnu.org/gnu/gcc/gcc-5.2.0/gcc-5.2.0.tar.bz2
#wget http://ftp.gnu.org/gnu/binutils/binutils-2.25.1.tar.bz2
popd

pushd $PREFIX
tar xvf ~/gcc-*.tar.bz2
tar xvf ~/binutils-*.tar.bz2
popd

mkdir -p $PREFIX/build-gcc
mkdir -p $PREFIX/build-binutils

pushd $PREFIX/build-gcc
../gcc-*/configure --target=$GCC_TARGET --prefix="$PREFIX" --disable-nls --enable-languages=c,c++ --without-headers
make all-gcc
make all-target-libgcc
make install-gcc
make install-target-libgcc
popd

pushd $PREFIX/build-binutils
../binutils-*/configure --target=$BINUTILS_TARGET --prefix="$PREFIX" --with-sysroot --disable-nls --disable-werror
make
make install
popd

