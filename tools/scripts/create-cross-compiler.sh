#!/bin/bash -e

# ------------------------------------------------------------------------------
# Silence
# ------------------------------------------------------------------------------

# This is used by Travic CI to prevent this script from overwhelming it's
# output. If there is too much output, Travis CI just gives up. The problem is,
# Travis CI uses output as a means to know that the script has not died. So
# we supress output here, and then use a script in Travis CI to ping it's
# watchdog every so often to keep this script alive.

if [ -n "${SILENCE+1}" ]; then
  exec 1>~/create-cross-compiler_stdout.log
  exec 2>~/create-cross-compiler_stderr.log
fi

# ------------------------------------------------------------------------------
# Checks
# ------------------------------------------------------------------------------

if [ ! -d "bfelf_loader" ]; then
    echo "The 'create-cross-compiler.sh' script must be run from the bareflank repo's root directory"
    echo $PWD
    exit 1
fi

# ------------------------------------------------------------------------------
# Environment
# ------------------------------------------------------------------------------

# Temp directory to build the sysroot in prior to installing the resulting
# binaries into the sysroot
export TMPDIR="$HOME/tmp-build-dir"

# The prefix is the place where all of the binaries and outputted content will
# be placed.
export PREFIX="$HOME/opt/cross"

# This is the resulting taget for the cross compiler. Note that at the moment
# the only supported platforms are x86_64. "ELF" is the resulting binary output,
# that is used by the different driver entry points (including Windows)
export TARGET=x86_64-elf

# The sysroot is the folder that resembles a unix system root. It should look
# like a normal filesystem, with a /lib, /include, etc... The compiler will use
# this system root to find it's resources.
export SYSROOT="$PREFIX/$TARGET"

# To make sure that the various different compilers can find outputted binaries
# we add the prefix to the path. Not that we don't add the sysroot to the path
# as this would conflict with "hosts" sysroot. Instead, the prefix is used as
# this contains the cross compilers with the target's name prepended to prevent
# confusion.
export PATH="$PREFIX/bin:$PATH"

# The following keeps track of which directory this script was executed from.
# Note that at the moment, we only support executing this script from the root
# folder of the hypervisor repo
export HYPERVISOR_ROOT=$PWD

# ------------------------------------------------------------------------------
# Downloads
# ------------------------------------------------------------------------------

# The following defines what packages we will downloaded and used to create
# the cross compiler (or at least the ones that can be modified)

if [ -z "$BINUTILS_URL" ]; then
    export BINUTILS_URL="http://ftp.gnu.org/gnu/binutils/binutils-2.25.1.tar.bz2"
fi

if [ -z "$GCC_URL" ]; then
    export GCC_URL="https://ftp.gnu.org/gnu/gcc/gcc-5.2.0/gcc-5.2.0.tar.bz2"
fi

if [ -z "$GCC_PATCH_URL" ]; then
    export GCC_PATCH_URL="https://raw.githubusercontent.com/Bareflank/hypervisor/master/tools/patches/gcc-5.2.0_bareflank.patch"
fi

if [ -z "$NASM_URL" ]; then
    export NASM_URL="http://www.nasm.us/pub/nasm/releasebuilds/2.11.08/nasm-2.11.08.tar.gz"
fi

if [ -z "$NEWLIB_URL" ]; then
    export NEWLIB_URL="ftp://sourceware.org/pub/newlib/newlib-2.3.0.20160104.tar.gz"
fi

if [ -z "$CMAKE_URL" ]; then
    export CMAKE_URL="https://cmake.org/files/v3.4/cmake-3.4.2.tar.gz"
fi

# ------------------------------------------------------------------------------
# Setup
# ------------------------------------------------------------------------------

if [ ! -d $TMPDIR ]; then
    rm -Rf $PREFIX
fi

if [ ! -d $TMPDIR ]; then
    mkdir -p $TMPDIR
fi

if [ ! -d $PREFIX/bin/ ]; then
    mkdir -p $PREFIX/bin/
fi

pushd $TMPDIR

# ------------------------------------------------------------------------------
# Fetch
# ------------------------------------------------------------------------------

if [ ! -d "binutils" ]; then
    wget --no-check-certificate $BINUTILS_URL
    tar xvf binutils-*.tar.bz2
    mv binutils-*/ binutils
fi

if [ ! -d "gcc" ]; then
    wget --no-check-certificate $GCC_URL
    tar xvf gcc-*.tar.bz2
    mv gcc-*/ gcc
fi

if [ ! -d "nasm" ]; then
    wget --no-check-certificate $NASM_URL
    tar xvf nasm-*.tar.gz
    mv nasm-*/ nasm
fi

if [ ! -d "newlib" ]; then
    wget --no-check-certificate $NEWLIB_URL
    tar xvf newlib-*.tar.gz
    mv newlib-*/ newlib
fi

if [ ! -d "cmake" ]; then
    wget --no-check-certificate $CMAKE_URL
    tar xvf cmake-*.tar.gz
    mv cmake-*/ cmake
fi

if [ ! -f "gcc_bareflank.patch" ]; then
    wget $GCC_PATCH_URL
    mv gcc-*_bareflank.patch gcc_bareflank.patch
fi

if [ ! -d "libbfc" ]; then
    git clone --depth 1 https://github.com/Bareflank/libbfc.git
fi

if [ ! -d "libcxxabi" ]; then
    git clone --depth 1 http://llvm.org/git/libcxxabi
fi

if [ ! -d "libcxx" ]; then
    git clone --depth 1 http://llvm.org/git/libcxx
fi

if [ ! -d "llvm" ]; then
    git clone --depth 1 http://llvm.org/git/llvm
fi

# ------------------------------------------------------------------------------
# Patches
# ------------------------------------------------------------------------------

if [ ! -f "completed_patch_gcc" ]; then

    pushd $TMPDIR/gcc/
    patch -p1 < ../gcc_bareflank.patch
    popd

    touch completed_patch_gcc
fi

# ------------------------------------------------------------------------------
# Install Wrapper
# ------------------------------------------------------------------------------

if [ ! -f "installed_bareflank_gcc_wrapper" ]; then

    rm -Rf $PREFIX/bin/x86_64-bareflank-gcc
    rm -Rf $PREFIX/bin/x86_64-bareflank-g++

    echo $HYPERVISOR_ROOT/tools/scripts/bareflank-gcc-wrapper

    ln -s $HYPERVISOR_ROOT/tools/scripts/bareflank-gcc-wrapper $PREFIX/bin/x86_64-bareflank-gcc
    ln -s $HYPERVISOR_ROOT/tools/scripts/bareflank-gcc-wrapper $PREFIX/bin/x86_64-bareflank-g++

    touch installed_bareflank_gcc_wrapper
fi

# ------------------------------------------------------------------------------
# Cmake
# ------------------------------------------------------------------------------

if [ ! -f "completed_build_cmake" ]; then

    rm -Rf build-cmake
    mkdir -p build-cmake

    pushd build-cmake
    ../cmake/configure
    make -j2
    sudo make -j2 install
    popd

    touch completed_build_cmake
fi

# ------------------------------------------------------------------------------
# Binutils
# ------------------------------------------------------------------------------

if [ ! -f "completed_build_binutils" ]; then

    rm -Rf build-binutils
    mkdir -p build-binutils

    pushd build-binutils
    ../binutils/configure --target=$TARGET --prefix="$PREFIX" --with-sysroot --disable-nls --disable-werror
    make -j2
    make -j2 install
    popd

    touch completed_build_binutils
fi

# ------------------------------------------------------------------------------
# GCC
# ------------------------------------------------------------------------------

if [ ! -f "completed_build_gcc" ]; then

    rm -Rf build-gcc
    mkdir -p build-gcc

    pushd build-gcc
    ../gcc/configure --target=$TARGET --prefix="$PREFIX" --disable-nls --enable-languages=c,c++ --without-headers
    make -j2 all-gcc
    make -j2 all-target-libgcc
    make -j2 install-gcc
    make -j2 install-target-libgcc
    popd

    touch completed_build_gcc
fi

# ------------------------------------------------------------------------------
# Nasm
# ------------------------------------------------------------------------------

if [ ! -f "completed_build_nasm" ]; then

    rm -Rf build-nasm
    cp -Rfav nasm build-nasm

    pushd build-nasm
    ./configure --prefix="$PREFIX"
    make -j2
    make -j2 install
    popd

    touch completed_build_nasm
fi

# ------------------------------------------------------------------------------
# Flags
# ------------------------------------------------------------------------------

# Note that these flags are used to compile the cross compiled code, so they
# have to be set after the cross compilers are compiled. If we don't do this,
# our cross compilers will be build with these flags which is wrong. Also
# note that we build the flags upon each other to ensure that the flags are
# consistent.

NEWLIB_DEFINES="$NEWLIB_DEFINES -D_HAVE_LONG_DOUBLE"
NEWLIB_DEFINES="$NEWLIB_DEFINES -D_LDBL_EQ_DBL"
NEWLIB_DEFINES="$NEWLIB_DEFINES -D_POSIX_TIMERS"
NEWLIB_DEFINES="$NEWLIB_DEFINES -U__STRICT_ANSI__"
NEWLIB_DEFINES="$NEWLIB_DEFINES -DMALLOC_PROVIDED"
NEWLIB_DEFINES="$NEWLIB_DEFINES -D_NEWLIB_VERSION"

LIBBFC_DEFINES="$LIBBFC_DEFINES -DSYM_PROVIDED__WRITE"
LIBBFC_DEFINES="$LIBBFC_DEFINES -DSYM_PROVIDED__MALLOC"
LIBBFC_DEFINES="$LIBBFC_DEFINES -DSYM_PROVIDED__FREE"
LIBBFC_DEFINES="$LIBBFC_DEFINES -DSYM_PROVIDED__CALLOC"
LIBBFC_DEFINES="$LIBBFC_DEFINES -DSYM_PROVIDED__REALLOC"

CFLAGS="$CFLAGS -fpic"
CFLAGS="$CFLAGS -ffreestanding"
CFLAGS="$CFLAGS -mno-red-zone"
CFLAGS="$CFLAGS $NEWLIB_DEFINES"

CXXFLAGS="$CXXFLAGS -fno-use-cxa-atexit"
CXXFLAGS="$CXXFLAGS -fno-threadsafe-statics"
CXXFLAGS="$CXXFLAGS $CFLAGS"

export CFLAGS=$CFLAGS
export CXXFLAGS=$CXXFLAGS

# ------------------------------------------------------------------------------
# Nasm
# ------------------------------------------------------------------------------

if [ ! -f "completed_build_newlib" ]; then

    rm -Rf build-newlib
    mkdir -p build-newlib

    pushd build-newlib
    ../newlib/configure --target=$TARGET --prefix=$PREFIX
    make -j2
    make -j2 install
    popd

    touch completed_build_newlib
fi

# ------------------------------------------------------------------------------
# BFC
# ------------------------------------------------------------------------------

if [ ! -f "completed_build_libbfc" ]; then

    rm -Rf build-libbfc
    mkdir -p build-libbfc

    pushd build-libbfc
    $PREFIX/bin/x86_64-bareflank-gcc $LIBBFC_DEFINES $CFLAGS -c ../libbfc/*.c
    $PREFIX/bin/x86_64-elf-ar rcs libbfc.a *.o
    cp -Rf libbfc.a $SYSROOT/lib/
    popd

    touch completed_build_libbfc
fi

# ------------------------------------------------------------------------------
# Libcxxabi
# ------------------------------------------------------------------------------

if [ ! -f "completed_build_libcxxabi" ]; then

    rm -Rf build-libcxxabi
    mkdir -p build-libcxxabi

    pushd build-libcxxabi
    cmake ../libcxxabi/ \
        -DLLVM_PATH=../llvm \
        -DLIBCXXABI_LIBCXX_PATH=../libcxx/ \
        -DCMAKE_INSTALL_PREFIX=$SYSROOT/ \
        -DLIBCXXABI_SYSROOT=$SYSROOT/ \
        -DCMAKE_C_COMPILER=$PREFIX/bin/x86_64-bareflank-gcc \
        -DCMAKE_CXX_COMPILER=$PREFIX/bin/x86_64-bareflank-g++ \
        -DLIBCXXABI_ENABLE_THREADS=OFF
    make -j2
    make -j2 install
    popd

    touch completed_build_libcxxabi
fi

# ------------------------------------------------------------------------------
# Libcxxabi
# ------------------------------------------------------------------------------

export BAREFLANK_WRAPPER_INCLUDE_LIBC=true

if [ ! -f "completed_build_libcxx" ]; then

    rm -Rf build-libcxx
    mkdir -p build-libcxx

    pushd build-libcxx
    cmake ../libcxx/ \
        -DLLVM_PATH=../llvm \
        -DLIBCXX_CXX_ABI=libcxxabi \
        -DLIBCXX_CXX_ABI_INCLUDE_PATHS=../libcxxabi/include \
        -DCMAKE_INSTALL_PREFIX=$SYSROOT/ \
        -DLIBCXX_SYSROOT=$SYSROOT/ \
        -DCMAKE_C_COMPILER=$PREFIX/bin/x86_64-bareflank-gcc \
        -DCMAKE_CXX_COMPILER=$PREFIX/bin/x86_64-bareflank-g++ \
        -DLIBCXX_ENABLE_THREADS=OFF \
        -DLIBCXX_ENABLE_MONOTONIC_CLOCK=OFF
    make -j2
    make -j2 install
    popd

    touch completed_build_libcxx
fi

export BAREFLANK_WRAPPER_INCLUDE_LIBC=false

# ------------------------------------------------------------------------------
# Copy
# ------------------------------------------------------------------------------

if [ ! -d $HYPERVISOR_ROOT/bfvmm/bin/cross ]; then
    mkdir -p $HYPERVISOR_ROOT/bfvmm/bin/cross
fi

cp -Rf $SYSROOT/lib/libc++.so.1.0 $HYPERVISOR_ROOT/bfvmm/bin/cross/libc++.so

# ------------------------------------------------------------------------------
# Done
# ------------------------------------------------------------------------------

popd
rm -Rf $TMPDIR
