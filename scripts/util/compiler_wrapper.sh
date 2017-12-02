#!/bin/bash -e
#
# Bareflank Hypervisor
# Copyright (C) 2015 Assured Information Security, Inc.
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

BIN_LOCATION="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# ------------------------------------------------------------------------------
# Compiler / Linker
# ------------------------------------------------------------------------------

TARGET_NAME=$(basename $0 | cut -d '-' -f 1)
SYSROOT_NAME=$(basename $0 | cut -d '-' -f 2)
PROGRAM_NAME=$(basename $0 | cut -d '-' -f 3)
VERSION_NAME=$(basename $0 | cut -d '-' -f 4)

# ------------------------------------------------------------------------------
# Compiler
# ------------------------------------------------------------------------------

if [[ -z $VERSION_NAME ]]; then
    COMPILER=$PROGRAM_NAME
else
    COMPILER=$PROGRAM_NAME-$VERSION_NAME
fi

LINKER="$BIN_LOCATION/${TARGET_NAME}-vmm-elf-ld"

# ------------------------------------------------------------------------------
# Mode Flags
# ------------------------------------------------------------------------------

argArray=("$@")

for ((i=0; i < ${#argArray[@]}; i++))
do
    case ${argArray[i]} in
    "-c")
        export COMPILE_ONLY="true"
        ;;

    "-shared")
        export SHARED_LIBRARY="true"
        ;;

    "-x")
        CXX_COMPILER="true"
        i=$((i+1))
        ;;

    "-o")
        export OUTPUT_FILE=${argArray[i+1]}
        export OUTPUT_FILE_BASE=$(basename $OUTPUT_FILE)
        i=$((i+1))
        ;;

    "-DNOSTDINC_C")
        export DISABLE_LIB_C="true"
        export DISABLE_INCLUDE_C="true"
        ;;

    "-DNOSTDINC_CXX")
        export DISABLE_LIB_CXX="true"
        export DISABLE_INCLUDE_CXX="true"
        ;;

    "-DNOSTDLIB_C")
        export DISABLE_LIB_C="true"
        ;;

    "-DNOSTDLIB_CXX")
        export DISABLE_LIB_CXX="true"
        ;;

    esac
done

# ------------------------------------------------------------------------------
# System Root
# ------------------------------------------------------------------------------

SYSROOT="$BIN_LOCATION/.."

# ------------------------------------------------------------------------------
# System Root Includes
# ------------------------------------------------------------------------------

SYSROOT_INC_PATH=""

if [[ -z $DISABLE_INCLUDE_C ]]; then

    if [[ -z $DISABLE_INCLUDE_CXX ]] && [[ $CXX_COMPILER == "true" ]] && [[ -d "$SYSROOT/include/c++/v1" ]]; then
        SYSROOT_INC_PATH="$SYSROOT_INC_PATH -isystem $SYSROOT/include/c++/v1"
    fi

    if [[ -d "$SYSROOT/include" ]]; then
        SYSROOT_INC_PATH="$SYSROOT_INC_PATH -isystem $SYSROOT/include"
    fi

fi

# ------------------------------------------------------------------------------
# System Root Libs
# ------------------------------------------------------------------------------

SYSROOT_LIB_PATH="-L$SYSROOT/lib"
# SYSROOT_LIB_PATH="${SYSROOT_LIB_PATH} -lc++ -lc++abi -lpthread -lbfunwind"
# SYSROOT_LIB_PATH="${SYSROOT_LIB_PATH} --whole-archive -lbfcrt --no-whole-archive -lc -lbfsyscall -lc"

# if [[ -z $DISABLE_LIB_C ]] && [[ ! $SHARED_LIBRARY == "true" ]]; then
#     if ls "$SYSROOT/lib/libc"* 1> /dev/null 2>&1 &&
#        ls "$SYSROOT/lib/libbfsyscall"* 1> /dev/null 2>&1 &&
#        ls "$SYSROOT/lib/libbfcrt"* 1> /dev/null 2>&1 ; then
#         if [[ -z $DISABLE_LIB_CXX ]] && [[ $CXX_COMPILER == "true" ]]; then
#             if ls "$SYSROOT/lib/libc++"* 1> /dev/null 2>&1; then
#                 SYSROOT_LIB_PATH="${SYSROOT_LIB_PATH} -lc++ -lc++abi -lpthread -lbfunwind"
#             fi
#         fi
#
#         SYSROOT_LIB_PATH="${SYSROOT_LIB_PATH} --whole-archive -lbfcrt --no-whole-archive -lc -lbfsyscall -lc"
#     fi
# fi

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

    "-DNOSTDINC_C")
        continue
        ;;

    "-DNOSTDINC_CXX")
        continue
        ;;

    "-DNOSTDLIB_C")
        continue
        ;;

    "-DNOSTDLIB_CXX")
        continue
        ;;

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

    "-x")
        COMPILE_ARGS[$COMPILE_ARGS_INDEX]="$ARG ${argArray[i+1]}"
        COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX+1))
        i=$((i+1))
        continue
        ;;

    "-o")
        if [[ $COMPILE_ONLY == "true" ]]; then
            COMPILE_ARGS[$COMPILE_ARGS_INDEX]="$ARG ${argArray[i+1]}"
            COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX+1))
        else
            LINK_ARGS[$LINK_ARGS_INDEX]="$ARG ${argArray[i+1]}"
            LINK_ARGS_INDEX=$((LINK_ARGS_INDEX+1))
        fi
        i=$((i+1))
        continue
        ;;

    "-m"*)
        COMPILE_ARGS[$COMPILE_ARGS_INDEX]=$ARG
        COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX+1))
        continue
        ;;

    "--fuse-ld="* | "-fuse-ld="*)
        if [[ "$ARG" == --fuse-ld=gold ]] || [[ "$ARG" == -fuse-ld=gold ]]; then
            LINKER="ld.gold"
        else
            LINKER=$(echo $ARG | cut -d '=' -f 2)
        fi
        continue
        ;;

    "--fuse-ld=lld" | "-fuse-ld=lld")
        LINKER="ld.lld-$VERSION_NAME"
        continue
        ;;

    "-flto"*)
        COMPILE_ARGS[$COMPILE_ARGS_INDEX]=$ARG
        COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX+1))

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
        ARG=${ARG//,/ }

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
        if [[ ! $COMPILE_ONLY == "true" ]]; then
            OBJECT_FILE_ARGS[$OBJECT_FILE_ARGS_INDEX]=$ARG
            OBJECT_FILE_ARGS_INDEX=$((OBJECT_FILE_ARGS_INDEX+1))
            continue
        fi
        ;;

    *".lo")
        if [[ ! $COMPILE_ONLY == "true" ]]; then
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
# Execute
# ------------------------------------------------------------------------------

LINK_OBJS_INDEX=0
LINK_OBJS[$LINK_OBJS_INDEX]=

if [[ -n "$SOURCE_ARGS" ]]; then

    if [[ ! $COMPILE_ONLY == "true" ]]; then
        COMPILE_ARGS[$COMPILE_ARGS_INDEX]="-c"
        COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX+1))

        for ((i=0; i < ${#SOURCE_ARGS[@]}; i++))
        do
            LINK_OBJS[$LINK_OBJS_INDEX]=${SOURCE_ARGS[i]%.*}.o
            LINK_OBJS_INDEX=$((LINK_OBJS_INDEX+1))
        done
    fi

    $COMPILER -U__USER_LABEL_PREFIX__ -D__USER_LABEL_PREFIX__="" -D__ELF__ --target=${TARGET_NAME}-elf -Qunused-arguments --sysroot=$SYSROOT $SYSROOT_INC_PATH ${COMPILE_ARGS[*]} $REQUIRED_COMPILER_ARGS ${SOURCE_ARGS[*]}

else

    if [[ -z "$OBJECT_FILE_ARGS" ]]; then
        $COMPILER ${COMPILE_ARGS[*]} $REQUIRED_COMPILER_ARGS
        exit 0
    fi

fi

if [[ $COMPILE_ONLY == "true" ]]; then
    exit 0
fi

$LINKER --sysroot=$SYSROOT ${OBJECT_FILE_ARGS[*]} ${LINK_OBJS[*]} ${LINK_ARGS[*]} $REQUIRED_LINKER_ARGS ${SYSROOT_LIB_PATH} -z max-page-size=4096 -z common-page-size=4096 -z relro -z now
