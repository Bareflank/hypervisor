#!/bin/bash -e

# Options:
#
# export SILENCE=true
#     Tells the script to redirect all output to a set of log files. This
#     is mainly used by Travis CI because it cannot handle all of the output
#     that this scripts spits out.
#
# export KEEP_TMP=true
#     Tells the script to keep the tmp directory when it's finished. This is
#     used by developers of this script so that you can work on the script
#     without having to recompile every step constantly. If you need to
#     re-execute a step, simply delete the associated "touch" portion of the
#     step, and it will re-execute your step, and any step that depends on
#     that step.
#
# export BINUTILS_URL=<url>
# export GCC_URL=<url>
# export GCC_PATCH_URL=<url>
# export NASM_URL=<url>
# export NEWLIB_URL=<url>
# export CMAKE_URL=<url>
#     Tells the script to use the URL for the package provided. This is also
#     used by Travis CI, but can be used by anyone, to taget specific versions
#     of software. For example, this can be used to create GCC 5.3.0 instead
#     of the default.
#
#     Note that not all versions of software are supported, so it's possible
#     that changing one of these might cause you to create a build environment
#     that is not supported. To see the list of supported variations, please
#     see the Travis CI script, or supporting documentation.
#

# ------------------------------------------------------------------------------
# Silence
# ------------------------------------------------------------------------------

# This is used by Travic CI to prevent this script from overwhelming it's
# output. If there is too much output, Travis CI just gives up. The problem is,
# Travis CI uses output as a means to know that the script has not died. So
# we supress output here, and then use a script in Travis CI to ping it's
# watchdog every so often to keep this script alive.

if [ -n "$SILENCE" ]; then
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
# Debugging
# ------------------------------------------------------------------------------

echo BINUTILS_URL = $BINUTILS_URL
echo GCC_URL = $GCC_URL
echo GCC_PATCH_URL = $GCC_PATCH_URL
echo NASM_URL = $NASM_URL
echo NEWLIB_URL = $NEWLIB_URL
echo CMAKE_URL = $CMAKE_URL

echo TMPDIR = $TMPDIR
echo PREFIX = $PREFIX
echo TARGET = $TARGET
echo SYSROOT = $SYSROOT
echo PATH = $PATH
echo HYPERVISOR_ROOT = $HYPERVISOR_ROOT

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

set -x

# ------------------------------------------------------------------------------
# Fetch
# ------------------------------------------------------------------------------

if [ ! -d "binutils" ]; then
    rm -Rf completed_build_binutils
    wget --no-check-certificate $BINUTILS_URL
    tar xvf binutils-*.tar.bz2
    mv binutils-*/ binutils
fi

if [ ! -d "gcc" ]; then
    rm -Rf completed_build_gcc
    wget --no-check-certificate $GCC_URL
    tar xvf gcc-*.tar.bz2
    mv gcc-*/ gcc
fi

if [ ! -d "nasm" ]; then
    rm -Rf completed_build_nasm
    wget --no-check-certificate $NASM_URL
    tar xvf nasm-*.tar.gz
    mv nasm-*/ nasm
fi

if [ ! -d "newlib" ]; then
    rm -Rf completed_build_newlib
    wget --no-check-certificate $NEWLIB_URL
    tar xvf newlib-*.tar.gz
    mv newlib-*/ newlib
fi

if [ ! -d "libbfc" ]; then
    rm -Rf completed_build_libbfc
    git clone --depth 1 https://github.com/Bareflank/libbfc.git
fi

if [ ! -d "libcxxabi" ]; then
    rm -Rf completed_build_libcxxabi
    git clone --depth 1 -b release_38 http://llvm.org/git/libcxxabi
fi

if [ ! -d "libcxx" ]; then
    rm -Rf completed_build_libcxx
    git clone --depth 1 -b release_38 http://llvm.org/git/libcxx
fi

if [ ! -d "llvm" ]; then
    git clone --depth 1 -b release_38 http://llvm.org/git/llvm
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
    ../gcc/configure --target=$TARGET --prefix="$PREFIX" --disable-nls --enable-languages=c,c++ --without-headers --without-isl
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

export NEWLIB_DEFINES="-D_HAVE_LONG_DOUBLE -D_LDBL_EQ_DBL -D_POSIX_TIMERS -U__STRICT_ANSI__ -DMALLOC_PROVIDED -D_NEWLIB_VERSION" 2> /dev/null
export LIBBFC_DEFINES="-DSYM_PROVIDED__WRITE -DSYM_PROVIDED__MALLOC -DSYM_PROVIDED__FREE -DSYM_PROVIDED__CALLOC -DSYM_PROVIDED__FSTAT -DSYM_PROVIDED__REALLOC" 2> /dev/null
export CFLAGS="-fpic -ffreestanding -mno-red-zone $NEWLIB_DEFINES" 2> /dev/null
export CXXFLAGS="-fno-use-cxa-atexit -fno-threadsafe-statics $CFLAGS" 2> /dev/null

# ------------------------------------------------------------------------------
# Newlib
# ------------------------------------------------------------------------------

if [ ! -f "completed_build_newlib" ]; then

    rm -Rf completed_build_libcxx

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
# CRT
# ------------------------------------------------------------------------------

if [ ! -f "completed_build_crt" ]; then

    rm -Rf completed_build_libcxx

    export BAREFLANK_WRAPPER_IGNORE_CRT=true 2> /dev/null

    pushd $HYPERVISOR_ROOT/bfcrt
    make clean
    make
    cp -Rf bin/cross/libbfcrt_static.a $SYSROOT/lib/
    popd

    export BAREFLANK_WRAPPER_IGNORE_CRT=false 2> /dev/null

    touch completed_build_crt
fi



# ------------------------------------------------------------------------------
# Unwind
# ------------------------------------------------------------------------------

if [ ! -f "completed_build_unwind" ]; then

    rm -Rf completed_build_libcxx

    pushd $HYPERVISOR_ROOT/bfunwind
    make clean
    make
    cp -Rf bin/cross/libbfunwind_static.a $SYSROOT/lib/
    popd

    touch completed_build_unwind
fi

# ------------------------------------------------------------------------------
# BFC
# ------------------------------------------------------------------------------

if [ ! -f "completed_build_libbfc" ]; then

    rm -Rf completed_build_libcxx

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

    rm -Rf $SYSROOT/include/c++
    rm -Rf completed_build_libcxx

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
        -DLIBCXXABI_ENABLE_THREADS=OFF \
        -DLIBCXXABI_ENABLE_SHARED=OFF
    make -j2
    make -j2 install
    popd

    touch completed_build_libcxxabi
fi

# ------------------------------------------------------------------------------
# Libcxx
# ------------------------------------------------------------------------------

if [ ! -f "completed_build_libcxx" ]; then

    rm -Rf $SYSROOT/include/c++
    rm -Rf completed_install_libcxx

    rm -Rf build-libcxx
    mkdir -p build-libcxx

    export BAREFLANK_WRAPPER_IS_LIBCXX=true 2> /dev/null

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

    export BAREFLANK_WRAPPER_IS_LIBCXX=false 2> /dev/null

    touch completed_build_libcxx
fi

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if [ ! -f "completed_install_libcxx" ]; then

    mkdir -p $HYPERVISOR_ROOT/bfvmm/bin/cross
    cp -Rf $SYSROOT/lib/libc++.so.1.0 $HYPERVISOR_ROOT/bfvmm/bin/cross/libc++.so

    touch completed_install_libcxx
fi

# ------------------------------------------------------------------------------
# Done
# ------------------------------------------------------------------------------

set +x

popd

if [ -n "$KEEP_TMP" ]; then
    echo "KEEP_TMP == true. You must manually delete: $TMPDIR"
else
    rm -Rf $TMPDIR
fi
