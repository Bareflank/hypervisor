# Linux Cross Compiler (GCC)

## Summary

The following describes how to create a cross-compiler for the Bareflank hypervisor on Linux. A script to automate this is provided in the repository.

## Apt

This guide was designed around a bare install of Debian 8.0 (Jessie). Prerequisites for building the cross compiler are satisfied using apt.

[Apt wiki](https://wiki.debian.org/Apt)

You will need to install the following:

```
apt-get install build-essential
apt-get install libgmp-dev
apt-get install libmpc-dev
apt-get install libmpfr-dev
apt-get install libisl-dev
apt-get install flex
apt-get install bison
```

## Downloads

Before you can compile the cross-compiler, you must download GCC and binutils. Note that you must select gcc 5.2.0 or higher, and binutils 2.25.1 or higher. All that is needed in this step are the links for the compiler you choose to install, as we will complete the actual download later. 

ftp://ftp.gnu.org/gnu/gcc/ <br>
ftp://ftp.gnu.org/gnu/binutils/ <br>
http://www.nasm.us/pub/nasm/releasebuilds/

## Compilation Environment

Before compilation can begin, you will be need to setup the compilation environment. First, you must setup some environment variables. _NOTE_: The Bareflank hypevisor uses these values (by default) to locate the cross-compiler. Therefore we do not recommend that you change these values unless you plan to provide the build environment with the location of the cross-compiler. 

```
export PREFIX="$HOME/opt/cross"
export TARGET=x86_64-elf
export PATH="$PREFIX/bin:$PATH"
```

Next, you must create a working directory, download and unpack GCC and binutils, and setup compilation folders for. __NOTE__: You must compile binutils and gcc outside of their source directories as shown below. Attempting to configure and compile them in their source directories will result in compilation errors. 

```
mkdir ~/cross
cd ~/cross

wget <link to gcc-*.tar.gz>
wget <link to binutils-*.tar.gz>
wget <link to nasm-*.tar.gz>

tar xvf gcc-*.tar.gz
tar xvf binutils-*.tar.gz
tar xvf nasm-*.tar.gz

mkdir build-gcc
mkdir build-binutils
```

## Compile binutils

To compile binutils, run the following:

```
cd ~/cross/build-binutils

../binutils-*/configure --target=$TARGET --prefix="$PREFIX" --with-sysroot --disable-nls --disable-werror

make
make install
```

Don’t use the “-j” option on make as it will error out (i.e. binutils and gcc do not successfully compile in a multicore environment).

## Compile gcc

To compile gcc, run the following:

```
cd ~/cross/build-gcc

../gcc-*/configure --target=$TARGET --prefix="$PREFIX" --disable-nls --enable-languages=c,c++ --without-headers

make all-gcc
make all-target-libgcc
make install-gcc
make install-target-libgcc
```

## Compile NASM

To compile nasm, run the following:

```
cd ~/cross/nasm-*

./configure --prefix="$PREFIX"
make 
make install
```

## Test

The resulting cross-compiler should be located at:

```
~/opt/cross/bin/x86_64-elf-gcc
~/opt/cross/bin/x86_64-elf-g++
~/opt/cross/bin/x86_64-elf-ld
~/opt/cross/bin/nasm
```
