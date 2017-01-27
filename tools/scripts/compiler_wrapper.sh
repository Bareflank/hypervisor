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
# Sysroot Directory
# ------------------------------------------------------------------------------

SYSROOT_NAME=`basename $0 | cut -d '-' -f 2`

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

DOCKER_ARGS="$DOCKER_ARGS -e SYSROOT_NAME=$SYSROOT_NAME -v $HYPER_ABS:$HYPER_ABS -v $BUILD_ABS:$BUILD_ABS -u $DOCKER_UID:$DOCKER_GID --rm -i bareflank/$compiler"

# ------------------------------------------------------------------------------
# Local / Docker Compiler
# ------------------------------------------------------------------------------

if [[ -d "$HOME/compilers/$compiler" ]]; then
    LOCAL_COMPILER="true"
    export PATH="$HOME/compilers/$compiler/bin/:$PATH"
fi

# ------------------------------------------------------------------------------
# Compiler
# ------------------------------------------------------------------------------

COMPILER="unsupported"

case $0 in

*"clang")
    if [[ $LOCAL_COMPILER == "true" ]]; then
        COMPILER="$HOME/compilers/$compiler/bin/clang --target=x86_64-elf -Qunused-arguments"
    else
        COMPILER="docker run $DOCKER_ARGS /tmp/compilers/$compiler/bin/clang --target=x86_64-elf -Qunused-arguments"
    fi
    ;;

*"clang++")
    if [[ $LOCAL_COMPILER == "true" ]]; then
        COMPILER="$HOME/compilers/$compiler/bin/clang++ --target=x86_64-elf -Qunused-arguments"
    else
        COMPILER="docker run $DOCKER_ARGS /tmp/compilers/$compiler/bin/clang++ --target=x86_64-elf -Qunused-arguments"
    fi
    ;;

*"ar")
    if [[ $LOCAL_COMPILER == "true" ]]; then
        COMPILER="$HOME/compilers/$compiler/bin/x86_64-elf-ar"
    else
        COMPILER="docker run $DOCKER_ARGS /tmp/compilers/$compiler/bin/x86_64-elf-ar"
    fi

    $COMPILER $@
    exit 0
    ;;

*"ranlib")
    if [[ $LOCAL_COMPILER == "true" ]]; then
        COMPILER="$HOME/compilers/$compiler/bin/x86_64-elf-ranlib"
    else
        COMPILER="docker run $DOCKER_ARGS /tmp/compilers/$compiler/bin/x86_64-elf-ranlib"
    fi

    $COMPILER $@
    exit 0
    ;;

*"nasm")
    if [[ $LOCAL_COMPILER == "true" ]]; then
        COMPILER="$HOME/compilers/$compiler/bin/nasm"
    else
        COMPILER="docker run $DOCKER_ARGS /tmp/compilers/$compiler/bin/nasm"
    fi

    $COMPILER $@
    exit 0
    ;;

*"docker")
    if [[ $LOCAL_COMPILER == "true" ]]; then
        COMPILER="eval SYSROOT_NAME=$SYSROOT_NAME"
    else
        COMPILER="docker run $DOCKER_ARGS"
    fi

    $COMPILER $@
    exit 0
    ;;

esac

if [[ $LOCAL_COMPILER == "true" ]]; then
    LINKER="$HOME/compilers/$compiler/bin/x86_64-elf-ld"
else
    LINKER="docker run $DOCKER_ARGS /tmp/compilers/$compiler/bin/x86_64-elf-ld"
fi

if [[ $COMPILER == "unsupported" ]]; then
    echo "You cannot use the wrapper directly. Instead, one of the provided symlinks"
    exit 1
fi

# ------------------------------------------------------------------------------
# Mode Flags
# ------------------------------------------------------------------------------

argArray=("$@")

for ((i=0; i < ${#argArray[@]}; i++))
do
    case ${argArray[i]} in
    "-c")
        COMPILE_ONLY="yes"
        ;;

    "-shared")
        SHARED_LIBRARY="yes"
        ;;

    "-o")
        OUTPUT_FILE=${argArray[i+1]}
        OUTPUT_FILE_BASE=`basename $OUTPUT_FILE`
        i=$((i+1))
        ;;

    "-soname")
        SONAME=${argArray[i+1]}
        i=$((i+1))
        ;;

    esac
done

if [[ $SHARED_LIBRARY == "yes" ]] && [[ -z $SONAME ]]; then
    REQUIRED_LINKER_ARGS="$REQUIRED_LINKER_ARGS -soname $OUTPUT_FILE_BASE"
fi

# ------------------------------------------------------------------------------
# Custom Variables
# ------------------------------------------------------------------------------

# %CUSTOM_VARIABLES%

# ------------------------------------------------------------------------------
# Newlib Defines
# ------------------------------------------------------------------------------

NEWLIB_DEFINES=""
NEWLIB_DEFINES="$NEWLIB_DEFINES -D_HAVE_LONG_DOUBLE"
NEWLIB_DEFINES="$NEWLIB_DEFINES -D_LDBL_EQ_DBL"
NEWLIB_DEFINES="$NEWLIB_DEFINES -D_POSIX_TIMERS"
NEWLIB_DEFINES="$NEWLIB_DEFINES -U__STRICT_ANSI__"
NEWLIB_DEFINES="$NEWLIB_DEFINES -DCLOCK_MONOTONIC"

# ------------------------------------------------------------------------------
# Filter Arguments
# ------------------------------------------------------------------------------

COMPILE_ARGS_INDEX=0
LINK_ARGS_INDEX=0
SOURCE_ARGS_INDEX=0
OBJECT_FILE_ARGS_INDEX=0

COMPILE_ARGS[$COMPILE_ARGS_INDEX]=
LINK_ARGS[$LINK_ARGS_INDEX]=
SOURCE_ARGS[$SOURCE_ARGS_INDEX]=
OBJECT_FILE_ARGS[$OBJECT_FILE_ARGS_INDEX]=

argArray=("$@")

for ((i=0; i < ${#argArray[@]}; i++))
do
    ARG=${argArray[i]}

    case $ARG in

    "-stdlib=libc++")
        continue
        ;;

    "-z defs")
        continue
        ;;

    "-mllvm")
        COMPILE_ARGS[$COMPILE_ARGS_INDEX]="$ARG ${argArray[i+1]}"
        COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX+1))
        i=$((i+1))
        continue
        ;;

    "-Xclang")
        COMPILE_ARGS[$COMPILE_ARGS_INDEX]="$ARG ${argArray[i+1]}"
        COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX+1))
        i=$((i+1))
        continue
        ;;

    "-m"*)
        COMPILE_ARGS[$COMPILE_ARGS_INDEX]=$ARG
        COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX+1))
        continue
        ;;

    "-flto"*)
        COMPILE_ARGS[$COMPILE_ARGS_INDEX]=$ARG
        COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX+1))

        # only use gold linker module for flto with clang
        if [[ $0 == *"clang"* ]]; then
            LINK_ARGS=("--plugin $HOME/compilers/$compiler/lib/LLVMgold.so" "${LINK_ARGS[@]}");
            LINK_ARGS_INDEX=$((LINK_ARGS_INDEX + 1));
        fi
        continue
        ;;

    "-f"*)
        COMPILE_ARGS[$COMPILE_ARGS_INDEX]=$ARG
        COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX+1))
        continue
        ;;

    "-D"*)
        if [[ $ARG == "-DPACKAGE"* ]]; then
            continue
        fi

        COMPILE_ARGS[$COMPILE_ARGS_INDEX]=$ARG
        COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX+1))
        continue
        ;;

    "-U"*)
        COMPILE_ARGS[$COMPILE_ARGS_INDEX]=$ARG
        COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX+1))
        continue
        ;;

    "-std"*)
        COMPILE_ARGS[$COMPILE_ARGS_INDEX]=$ARG
        COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX+1))
        continue
        ;;

    "-nodefaultlibs")
        COMPILE_ARGS[$COMPILE_ARGS_INDEX]=$ARG
        COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX+1))
        continue
        ;;

    "-Xlinker")
        LINK_ARGS[$LINK_ARGS_INDEX]="${argArray[i+1]}"
        LINK_ARGS_INDEX=$((LINK_ARGS_INDEX+1))
        i=$((i+1))
        continue
        ;;

    "-rdynamic")
        LINK_ARGS[$LINK_ARGS_INDEX]="-export-dynamic"
        LINK_ARGS_INDEX=$((LINK_ARGS_INDEX+1))
        continue
        ;;

    "-Wl,"*)
        COMPILE_ARGS[$COMPILE_ARGS_INDEX]=$ARG
        COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX+1))
        ARG=${ARG/-Wl,/}
        ARG=${ARG/,/ }

        if [[ $ARG == "-z defs" ]]; then
            continue
        fi

        LINK_ARGS[$LINK_ARGS_INDEX]=$ARG
        LINK_ARGS_INDEX=$((LINK_ARGS_INDEX+1))
        continue
        ;;

    "-W"*)
        COMPILE_ARGS[$COMPILE_ARGS_INDEX]=$ARG
        COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX+1))
        continue
        ;;

    *".c")
        SOURCE_ARGS[$SOURCE_ARGS_INDEX]=$ARG
        SOURCE_ARGS_INDEX=$((SOURCE_ARGS_INDEX+1))
        continue
        ;;

    *".cpp")
        SOURCE_ARGS[$SOURCE_ARGS_INDEX]=$ARG
        SOURCE_ARGS_INDEX=$((SOURCE_ARGS_INDEX+1))
        continue
        ;;

    *".cxx")
        SOURCE_ARGS[$SOURCE_ARGS_INDEX]=$ARG
        SOURCE_ARGS_INDEX=$((SOURCE_ARGS_INDEX+1))
        continue
        ;;

    *".S")
        SOURCE_ARGS[$SOURCE_ARGS_INDEX]=$ARG
        SOURCE_ARGS_INDEX=$((SOURCE_ARGS_INDEX+1))
        continue
        ;;

    *".o")
        if [[ ! $COMPILE_ONLY == "yes" ]]; then
            OBJECT_FILE_ARGS[$OBJECT_FILE_ARGS_INDEX]=$ARG
            OBJECT_FILE_ARGS_INDEX=$((OBJECT_FILE_ARGS_INDEX+1))
            continue
        fi
        ;;

    esac

    COMPILE_ARGS[$COMPILE_ARGS_INDEX]=$ARG
    COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX+1))

    LINK_ARGS[$LINK_ARGS_INDEX]=$ARG
    LINK_ARGS_INDEX=$((LINK_ARGS_INDEX+1))

done

# ------------------------------------------------------------------------------
# System Root Includes
# ------------------------------------------------------------------------------

SYSROOT_INC_PATH=""

if [[ -d "$HOME/compilers/$compiler/lib/clang/3.*/include/" ]]; then
    SYSROOT_INC_PATH="$SYSROOT_INC_PATH -isystem $HOME/compilers/$compiler/lib/clang/3.*/include/"
fi

if [[ -d "$HOME/compilers/$compiler/x86_64-elf/include/" ]]; then
    SYSROOT_INC_PATH="$SYSROOT_INC_PATH -isystem $HOME/compilers/$compiler/x86_64-elf/include/"
fi

if [[ -d "$BUILD_ABS/sysroot_$SYSROOT_NAME/x86_64-elf/include/" ]]; then
    SYSROOT_INC_PATH="$SYSROOT_INC_PATH -isystem $BUILD_ABS/sysroot_$SYSROOT_NAME/x86_64-elf/include/"
fi

if [[ -d "$BUILD_ABS/sysroot_$SYSROOT_NAME/x86_64-elf/include/c++/v1/" ]]; then
    SYSROOT_INC_PATH="$SYSROOT_INC_PATH -isystem $BUILD_ABS/sysroot_$SYSROOT_NAME/x86_64-elf/include/c++/v1/"
fi

# ------------------------------------------------------------------------------
# System Root Libs
# ------------------------------------------------------------------------------

SYSROOT_LIB_PATH="-L$BUILD_ABS/sysroot_$SYSROOT_NAME/x86_64-elf/lib/ -L$BUILD_ABS/sysroot_$SYSROOT_NAME/x86_64-elf/lib/cross"

# ------------------------------------------------------------------------------
# Execute
# ------------------------------------------------------------------------------

if [[ -n "$SOURCE_ARGS" ]]; then

    if [[ ! $COMPILE_ONLY == "yes" ]]; then
        COMPILE_ARGS[$COMPILE_ARGS_INDEX]="-c"
        COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX+1))
    fi

    $COMPILER $NEWLIB_DEFINES $SYSROOT_INC_PATH ${COMPILE_ARGS[*]} $REQUIRED_COMPILER_ARGS ${SOURCE_ARGS[*]}
fi

if [[ $COMPILE_ONLY == "yes" ]]; then
    exit 0
fi

$LINKER ${SYSROOT_LIB_PATH} ${OBJECT_FILE_ARGS[*]} ${LINK_ARGS[*]} $REQUIRED_LINKER_ARGS -z max-page-size=4096 -z common-page-size=4096 -z relro -z now
