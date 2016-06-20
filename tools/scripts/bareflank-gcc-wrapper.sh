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

%ENV_SOURCE%

# ------------------------------------------------------------------------------
# Docker Setup
# ------------------------------------------------------------------------------

if [[ -f /.dockerenv ]]; then
    HOME=/tmp
fi

DOCKER_UID=`id -u $USER`
DOCKER_GID=`id -g $USER`

for dir in $BUILD_ABS/extensions/*
do
    if [[ ! -d "$dir" ]]; then
        continue
    fi

    abs_dir=`cd $dir; pwd -P`

    DOCKER_ARGS="-v $abs_dir:$abs_dir $DOCKER_ARGS"

done

DOCKER_ARGS="$DOCKER_ARGS -v $HYPER_ABS:$HYPER_ABS -v $BUILD_ABS:$BUILD_ABS -u $DOCKER_UID:$DOCKER_GID --rm -i bareflank/$compiler"

# ------------------------------------------------------------------------------
# Local / Docker Compiler
# ------------------------------------------------------------------------------

if [[ -f "$HOME/compilers/$compiler/bin/x86_64-elf-gcc" ]]; then
    LOCAL_COMPILER="true"
fi

# ------------------------------------------------------------------------------
# Compiler
# ------------------------------------------------------------------------------

COMPILER="unsupported"

if [[ $0 == *"gcc" ]]; then
    if [[ $LOCAL_COMPILER == "true" ]]; then
        COMPILER="$HOME/compilers/$compiler/bin/x86_64-elf-gcc"
    else
        COMPILER="docker run $DOCKER_ARGS /tmp/compilers/$compiler/bin/x86_64-elf-gcc"
    fi
fi

if [[ $0 == *"g++" ]]; then
    if [[ $LOCAL_COMPILER == "true" ]]; then
        COMPILER="$HOME/compilers/$compiler/bin/x86_64-elf-g++"
    else
        COMPILER="docker run $DOCKER_ARGS /tmp/compilers/$compiler/bin/x86_64-elf-g++"
    fi
fi

if [[ $0 == *"ar" ]]; then
    if [[ $LOCAL_COMPILER == "true" ]]; then
        COMPILER="$HOME/compilers/$compiler/bin/x86_64-elf-ar"
    else
        COMPILER="docker run $DOCKER_ARGS /tmp/compilers/$compiler/bin/x86_64-elf-ar"
    fi

    $COMPILER $@
    exit 0
fi

if [[ $0 == *"nasm" ]]; then
    if [[ $LOCAL_COMPILER == "true" ]]; then
        COMPILER="$HOME/compilers/$compiler/bin/nasm"
    else
        COMPILER="docker run $DOCKER_ARGS /tmp/compilers/$compiler/bin/nasm"
    fi

    $COMPILER $@
    exit 0
fi

if [[ $0 == *"docker" ]]; then
    if [[ $LOCAL_COMPILER == "true" ]]; then
        COMPILER="eval"
    else
        COMPILER="docker run $DOCKER_ARGS"
    fi

    $COMPILER $@
    exit 0
fi

if [[ $COMPILER == "unsupported" ]]; then
    echo "You cannot use the wrapper directly. Instead, use a symlink that ends in gcc or g++"
    exit 1
fi

# ------------------------------------------------------------------------------
# Mode
# ------------------------------------------------------------------------------

MODE="link"
TYPE="binary"

for ARG in "$@"
do
    if [[ $ARG == "-c" ]]; then
        MODE="compile"
    fi

    if [[ $ARG == "-shared" ]]; then
        TYPE="shared"
    fi
done

# ------------------------------------------------------------------------------
# Unsupported
# ------------------------------------------------------------------------------

UNSUPPORTED=false

for ARG in "$@"
do
    if [[ $MODE == "link" ]]; then
        if [[ $ARG == *".c" ]]; then
            UNSUPPORTED=true
        fi
        if [[ $ARG == *".cpp" ]]; then
            UNSUPPORTED=true
        fi
    fi
done

if [[ $UNSUPPORTED == "true" ]]; then
    echo "Compiling and linking at the same time is not supported. Use -c"
    exit 1
fi

# ------------------------------------------------------------------------------
# Convert Arguments
# ------------------------------------------------------------------------------

i=0
CONVERTED_ARGS[$i]=

for ARG in "$@"
do

    if [[ $MODE == "link" ]]; then

        # We need to convert the GCC syntax for passing LD flags to LD so that
        # LD is getting the correct settings.
        if [[ $ARG == "-Wl,"* ]]; then
            ARG=${ARG/-Wl,/}
            ARG=${ARG/,/ }
        fi

        # GCC's syntax is different than LD's for this option.
        if [[ $ARG == "-rdynamic" ]]; then
            ARG="-export-dynamic"
        fi

    fi

    CONVERTED_ARGS[$i]=$ARG
    i=$((i + 1))

done

# ------------------------------------------------------------------------------
# Filter Arguments
# ------------------------------------------------------------------------------

i=0
ARGS[$i]=

for ARG in "${CONVERTED_ARGS[@]}"
do

    if [[ $MODE == "link" ]]; then

        # These flags are all specific to GCC and are not used by LD. CMake
        # will send these to GCC, and GCC filters them similar to what we
        # do here.
        if [[ $ARG == "-m"* ]]; then continue; fi
        if [[ $ARG == "-f"* ]]; then continue; fi
        if [[ $ARG == "-W"* ]]; then continue; fi
        if [[ $ARG == "-D"* ]]; then continue; fi
        if [[ $ARG == "-U"* ]]; then continue; fi

        # For some reason, Libc++abi turns this on for a shared library, and
        # we really don't want it as we provide the symbols as needed. In
        # general if this is enabled, we should disable it.
        if [[ $ARG == "-z defs" ]]; then
            echo "WARNING: -z defs disabled by bareflank-gcc-wrapper"
            continue;
        fi

        # These are not used by LD, and actually cause LD to do some pretty
        # terrible things. For example, nodefaults tells LD to use "-n" which
        # changes the permissions from RE/RW -> RWE which is really bad.
        if [[ $ARG == "-std"* ]]; then continue; fi
        if [[ $ARG == "-nodefaultlibs" ]]; then continue; fi

    fi

    ARGS[$i]=$ARG
    i=$((i + 1))

done

# ------------------------------------------------------------------------------
# Sysroot Libraries
# ------------------------------------------------------------------------------

# By default, bareflank does not support the use of libc or libc++ as static
# libraries. Instead, libc is only used to create libc++, and libc++ must
# be loaded at runtime, and thus does not need to be known during linking. The
# only thing the hypervisor code should need from the sysroot is the includes.

if [[ $BAREFLANK_WRAPPER_IS_LIBCXX == "true" ]]; then
    SYSROOT_LIBS+="-lc -lbfc -lbfunwind_static "
    SYSROOT_LIBS+="-u __cxa_throw_bad_array_new_length"
fi

SYSROOT_LIB_PATH="-L$BUILD_ABS/makefiles/bfcrt/bin/cross/ -L$BUILD_ABS/makefiles/bfunwind/bin/cross/ -L$BUILD_ABS/sysroot/x86_64-elf/lib/ "

# ------------------------------------------------------------------------------
# Sysroot Includes
# ------------------------------------------------------------------------------

SYSROOT_INC_PATH="-isystem $HOME/compilers/$compiler/x86_64-elf/include/ -isystem $BUILD_ABS/sysroot/x86_64-elf/include/ "

# REMOVE ME ***
# This is a dirty hack that makes sure the newlib header is there. This should
# go away once we have our own libc
# Note that there is another bug where running make more than once will cause
# the libcrt and libunwind to get compiled twice. This is because the includes
# change once installed. This will also get fixed once we have our own newlib
if [[ -f "$BUILD_ABS/sysroot/x86_64-elf/include/newlib.h" ]]; then
    SYSROOT_INC_PATH="-include $BUILD_ABS/sysroot/x86_64-elf/include/newlib.h $SYSROOT_INC_PATH"
fi

# This is a dirty hack that is needed for libcxx and libcxxabi. Basically, if
# they can see the headers in the sysroot, they gets all sorts of mad.
if [[ ! $BAREFLANK_WRAPPER_IS_LIBCXXABI == "true" && ! $BAREFLANK_WRAPPER_IS_LIBCXX == "true" ]]; then
    SYSROOT_INC_PATH="-I$BUILD_ABS/sysroot/x86_64-elf/include/c++/v1/ $SYSROOT_INC_PATH"
fi

# ------------------------------------------------------------------------------
# Libgcc
# ------------------------------------------------------------------------------

if [[ ! `pwd` == *"bfcrt"* && ! `pwd` == *"bfunwind"* ]]; then
    if [[ $MODE == "link" ]] && [[ $TYPE == "shared" ]]; then
        BAREFLANK_LIBS="-u local_init -u local_fini -lbfcrt_static "
    fi
fi

# ------------------------------------------------------------------------------
# Execute
# ------------------------------------------------------------------------------

if [ ! -z "$VERBOSE" ]; then
    echo "ARGS: $@"
    echo "MODE: $MODE"
    echo "COMPILER: $COMPILER"
    echo "FILTERED ARGS: ${ARGS[*]}"
    echo "SYSROOT_LIBS: $SYSROOT_LIBS"
    echo "SYSROOT_LIB_PATH: $SYSROOT_LIB_PATH"
    echo "SYSROOT_INC_PATH: $SYSROOT_INC_PATH"
    echo "BAREFLANK_LIBS: $BAREFLANK_LIBS"
    echo ""
fi

if [[ $MODE == "compile" ]]; then
    $COMPILER $SYSROOT_INC_PATH ${ARGS[*]}
fi

if [[ $MODE == "link" ]]; then

    if [[ $LOCAL_COMPILER == "true" ]]; then
        LINKER="$HOME/compilers/$compiler/bin/x86_64-elf-ld"
    else
        LINKER="docker run $DOCKER_ARGS /tmp/compilers/$compiler/bin/x86_64-elf-ld"
    fi

    $LINKER ${ARGS[*]} $SYSROOT_LIB_PATH $SYSROOT_LIBS $BAREFLANK_LIBS -z max-page-size=4096 -z relro -z now
fi
