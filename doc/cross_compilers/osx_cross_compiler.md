# OS X Cross Compiler

## Summary

The following describes how to create a cross-compiler for the Bareflank hypervisor.  

## Homebrew

Prior to being able to create the cross-compiler, you will need to install Homebrew. Homebrew provides access to some prerequisites needed to compile GCC and binutils. Note that some instructions online demonstrate how to compile these prerequisites manually, a process that should be avoided as this cross-compiler will be executing on the host, and thus should be as compatible with the host as possible. 

[Homebrew Main Page](http://brew.sh/)

Follow the instructions on the website for installing Homebrew (it’s insanely simple). Once installed you will need to install the following:

```
brew install gmp
brew install mpfr
brew install libmpc
brew install isl
```

## Downloads

Before you can compile the cross-compiler, you must download it. For GCC, this consists of both binutils and gcc itself. Note that you must select gcc 5.2.0 or higher, and binutils 2.25.1 or higher. All that is needed in this step are the links for the compiler you choose to install, as we will complete the actual download later. 

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

../gcc-*/configure --target=$TARGET --prefix="$PREFIX" --disable-nls --enable-languages=c,c++ --without-headers --with-gmp=/usr/local/Cellar/gmp/6.0.0a/ --with-mpfr=/usr/local/Cellar/mpfr/3.1.3/ --with-mpc=/usr/local/Cellar/libmpc/1.0.3/ --with-isl=/usr/local/Cellar/isl/0.14.1/

make all-gcc
make all-target-libgcc
make install-gcc
make install-target-libgcc
```

Note that the paths for gmp, mpfr, mpc and isl are hardcoded for OS X El Capitan and might be different depending on which version of OS X and Homebrew that you are using. 

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
