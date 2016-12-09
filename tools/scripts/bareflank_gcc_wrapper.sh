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

if [[ -d "$HOME/compilers/$compiler" ]]; then
    LOCAL_COMPILER="true"
    export PATH="$HOME/compilers/$compiler/bin/:$PATH"
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

if [[ $0 == *"clang" ]]; then
    if [[ $LOCAL_COMPILER == "true" ]]; then
        COMPILER="$HOME/compilers/$compiler/bin/clang --target=x86_64-elf -Qunused-arguments"
    else
        COMPILER="docker run $DOCKER_ARGS /tmp/compilers/$compiler/bin/clang --target=x86_64-elf -Qunused-arguments"
    fi
fi

if [[ $0 == *"g++" ]]; then
    if [[ $LOCAL_COMPILER == "true" ]]; then
        COMPILER="$HOME/compilers/$compiler/bin/x86_64-elf-g++"
    else
        COMPILER="docker run $DOCKER_ARGS /tmp/compilers/$compiler/bin/x86_64-elf-g++"
    fi
fi

if [[ $0 == *"clang++" ]]; then
    if [[ $LOCAL_COMPILER == "true" ]]; then
        COMPILER="$HOME/compilers/$compiler/bin/clang++ --target=x86_64-elf -Qunused-arguments"
    else
        COMPILER="docker run $DOCKER_ARGS /tmp/compilers/$compiler/bin/clang++ --target=x86_64-elf -Qunused-arguments"
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

for ARG in "$@"
do
    if [[ $ARG == "-c" ]]; then
        COMPILE_ONLY="yes"
        continue;
    fi
done

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

# store CLI arguments in an array for direct iteration
argArray=("$@")

# We store values in two lists, one for compiler options: COMPILER_ARGS
# and the other for linker options: LINK_ARGS.
# The algorithm filters known compiler flags from the CLI Args, and sores
# them in LINK_ARGS. Similarly we filter most linker options from the CLI
# Args, and store them in COMPILER_ARGS.
#
# We loop over the argArray directly, so we can handle positional arguments
# and not separate a positional argument from its preceding options
# By only using 2 lists, we are able to preserve the order of CLI Arguments
#
# This system is a brittle, and relies completely on the correctness of
# the conditional checks implemented within this block, as well as the order
# in which options are filtered. In essence we are reimplementing a
# functionality built into standard compilers without using the full list
# of compiler options. If it was desirable to use a compiler with
# different flags, such as the Intel compiler, this script will need to
# be refactored to handle the different arguments. As it is, there are
# likely edge cases where the correctness of this solution will fail.
# For example any linker arguments prefixed with a '-m' will not be
# correctly passed to the linker, as we identify them as compiler options.
for ((i=0; i < ${#argArray[@]}; i++))
do
    # get next argument
    ARG=${argArray[i]};

    # Ignored Flags
    if [[ $ARG == "-stdlib=libc++" ]]; then
        continue;
    fi

    if [[ $ARG == "-z defs" ]]; then
        continue;
    fi

    # Compile Only Flags

    # -mllvm takes a positional argument afterwards
    if [[ $ARG == "-mllvm" ]]; then
        COMPILE_ARGS[$COMPILE_ARGS_INDEX]="$ARG ${argArray[i+1]}";
        COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX + 1));
        ((i++));
        continue;
    fi

    # -Xclang takes a positional argument afterwards
    if [[ $ARG == "-Xclang" ]]; then
        COMPILE_ARGS[$COMPILE_ARGS_INDEX]="$ARG ${argArray[i+1]}";
        COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX + 1));
        ((i++));
        continue;
    fi

    if [[ $ARG == "-m"* ]]; then
        COMPILE_ARGS[$COMPILE_ARGS_INDEX]=$ARG;
        COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX + 1));
        continue;
    fi

    if [[ $ARG == "-f"* ]]; then
        COMPILE_ARGS[$COMPILE_ARGS_INDEX]=$ARG;
        COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX + 1));
        continue;
    fi

    if [[ $ARG == "-D"* ]]; then

        if [[ $ARG == "-DPACKAGE"* ]]; then
            continue
        fi

        COMPILE_ARGS[$COMPILE_ARGS_INDEX]=$ARG;
        COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX + 1));
        continue;
    fi

    if [[ $ARG == "-U"* ]]; then
        COMPILE_ARGS[$COMPILE_ARGS_INDEX]=$ARG;
        COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX + 1));
        continue;
    fi

    if [[ $ARG == "-std"* ]]; then
        COMPILE_ARGS[$COMPILE_ARGS_INDEX]=$ARG;
        COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX + 1));
        continue;
    fi

    if [[ $ARG == "-nodefaultlibs" ]]; then
        COMPILE_ARGS[$COMPILE_ARGS_INDEX]=$ARG;
        COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX + 1));
        continue;
    fi

    # Link Only Flags

    if [[ $ARG == "-Xlinker" ]]; then
        COMPILE_ARGS[$COMPILE_ARGS_INDEX]="$ARG ${argArray[i+1]}";
        COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX + 1));
        ((i++));
        continue;
    fi


    if [[ $ARG == "-rdynamic" ]]; then
        LINK_ARGS[$LINK_ARGS_INDEX]="-export-dynamic"
        LINK_ARGS_INDEX=$((LINK_ARGS_INDEX + 1));
        continue;
    fi

    # -W options must be handled together, in order from strongest to weakest
    # this compiler option must be handled after other -W arguments are processed

    # This is a specific set of options for passing arguments to the gold linker
    # for plugin support
    if [[ $ARG == "-Wl,--plugin-opt"* ]]; then
        COMPILE_ARGS[$COMPILE_ARGS_INDEX]=$ARG;
        COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX + 1));
        ARG=${ARG/-Wl,/}
        ARG=${ARG/,/ }
        LINK_ARGS[$LINK_ARGS_INDEX]="--plugin $HOME/compilers/$compiler/lib/LLVMgold.so $ARG";
        LINK_ARGS_INDEX=$((LINK_ARGS_INDEX + 1));
        continue;
    fi

    ## pass arguments directly to the linker through the compiler
    if [[ $ARG == "-Wl,"* ]]; then

        # store original arg in temp variable for use in COMPILE_ARGS
        myTemp=$ARG;
        ARG=${ARG/-Wl,/}
        ARG=${ARG/,/ }

        # we must be careful not to pass -z defs to libc++abi
        if [[ $ARG == "-z defs" ]]; then
            continue;
        fi

        LINK_ARGS[$LINK_ARGS_INDEX]=$ARG;
        LINK_ARGS_INDEX=$((LINK_ARGS_INDEX + 1));

        COMPILE_ARGS[$COMPILE_ARGS_INDEX]=$myTemp;
        COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX + 1));
        continue;
    fi

    # add any remaining -W args to COMPILE_ARGS
    if [[ $ARG == "-W"* ]]; then
        COMPILE_ARGS[$COMPILE_ARGS_INDEX]=$ARG;
        COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX + 1));
        continue;
    fi

    # Source Files
    if [[ $ARG == *".c" ]]; then
        SOURCE_ARGS[$SOURCE_ARGS_INDEX]=$ARG;
        SOURCE_ARGS_INDEX=$((SOURCE_ARGS_INDEX + 1));
        continue;
    fi

    if [[ $ARG == *".cpp" ]]; then
        SOURCE_ARGS[$SOURCE_ARGS_INDEX]=$ARG;
        SOURCE_ARGS_INDEX=$((SOURCE_ARGS_INDEX + 1));
        continue;
    fi

    if [[ $ARG == *".cxx" ]]; then
        SOURCE_ARGS[$SOURCE_ARGS_INDEX]=$ARG;
        SOURCE_ARGS_INDEX=$((SOURCE_ARGS_INDEX + 1));
        continue;
    fi

    if [[ $ARG == *".S" ]]; then
        SOURCE_ARGS[$SOURCE_ARGS_INDEX]=$ARG;
        SOURCE_ARGS_INDEX=$((SOURCE_ARGS_INDEX + 1));
        continue;
    fi

    # Object Files
    if [[ $ARG == *".o" ]] && [[ ! $COMPILE_ONLY == "yes" ]]; then
        OBJECT_FILE_ARGS[$OBJECT_FILE_ARGS_INDEX]=$ARG;
        OBJECT_FILE_ARGS_INDEX=$((OBJECT_FILE_ARGS_INDEX + 1));
        continue;
    fi

    # Common Flags, for both linker and compiler are thus far unclassified,
    # so add them to each list to preserve argument ordering
    COMPILE_ARGS[$COMPILE_ARGS_INDEX]=$ARG;
    COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX + 1));

    LINK_ARGS[$LINK_ARGS_INDEX]=$ARG;
    LINK_ARGS_INDEX=$((LINK_ARGS_INDEX + 1));
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

if [[ -d "$BUILD_ABS/sysroot/x86_64-elf/include/" ]]; then
    SYSROOT_INC_PATH="$SYSROOT_INC_PATH -isystem $BUILD_ABS/sysroot/x86_64-elf/include/"
fi

if [[ -d "$BUILD_ABS/sysroot/x86_64-elf/include/c++/v1/" ]]; then
    SYSROOT_INC_PATH="$SYSROOT_INC_PATH -isystem $BUILD_ABS/sysroot/x86_64-elf/include/c++/v1/"
fi

# ------------------------------------------------------------------------------
# Execute
# ------------------------------------------------------------------------------

if [[ -n "$SOURCE_ARGS" ]]; then

    if [[ ! $COMPILE_ONLY == "yes" ]]; then
        COMPILE_ARGS[$COMPILE_ARGS_INDEX]="-c";
        COMPILE_ARGS_INDEX=$((COMPILE_ARGS_INDEX + 1));
    fi

    $COMPILER $SYSROOT_INC_PATH ${COMPILE_ARGS[*]} ${SOURCE_ARGS[*]}
fi

if [[ $COMPILE_ONLY == "yes" ]]; then
    exit 0
fi

$LINKER  ${OBJECT_FILE_ARGS[*]} ${LINK_ARGS[*]} -z max-page-size=4096 -z common-page-size=4096 -z relro -z now
