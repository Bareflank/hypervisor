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

# ------------------------------------------------------------------------------
# Checks
# ------------------------------------------------------------------------------

case $(uname -o) in
Cygwin)
    ;;
*)
    echo "This script can only be used with: Cygwin"
    exit 1
esac

if [[ ! -d "bfelf_loader" ]]; then
    echo "This script must be run from bareflank root directory"
    exit 1
fi

# ------------------------------------------------------------------------------
# Help
# ------------------------------------------------------------------------------

option_help() {
    echo -e "Usage: setup-ubuntu.sh [OPTION]"
    echo -e "Sets up the system to compile / use Bareflank"
    echo -e ""
    echo -e "       -h, --help                       show this help menu"
    echo -e "       -l, --local                      setup local cross compilers"
    echo -e "       -n, --no-configure               skip the configure step"
    echo -e "       -g, --compiler <dirname>         directory of cross compiler"
    echo -e "       -o, --out_of_tree <dirname>      setup out of tree build"
    echo -e ""
}

# ------------------------------------------------------------------------------
# Functions
# ------------------------------------------------------------------------------

install_common_packages() {
    setup-x86_64.exe -q -P wget
    setup-x86_64.exe -q -P make
    setup-x86_64.exe -q -P gcc-core
    setup-x86_64.exe -q -P gcc-g++
    setup-x86_64.exe -q -P diffutils
    setup-x86_64.exe -q -P libgmp-devel
    setup-x86_64.exe -q -P libmpfr-devel
    setup-x86_64.exe -q -P libmpc-devel
    setup-x86_64.exe -q -P flex
    setup-x86_64.exe -q -P bison
    setup-x86_64.exe -q -P nasm
    setup-x86_64.exe -q -P texinfo
    setup-x86_64.exe -q -P cmake
    setup-x86_64.exe -q -P unzip
}

setup_ewdk() {
    if [[ ! -d /cygdrive/c/ewdk ]]; then
        wget https://go.microsoft.com/fwlink/p/?LinkID=699461 -O /tmp/ewdk.zip
        unzip /tmp/ewdk.zip -d /cygdrive/c/ewdk/
        chown -R $USER:SYSTEM /cygdrive/c/ewdk
        icacls.exe `cygpath -w /cygdrive/c/ewdk` /reset /T
        rm -Rf /tmp/ewdk.zip
    fi
}

# ------------------------------------------------------------------------------
# Arguments
# ------------------------------------------------------------------------------

while [[ $# -ne 0 ]]; do

    if [[ $1 == "-h" ]] || [[ $1 == "--help" ]]; then
        option_help
        exit 0
    fi

    if [[ $1 == "-l" ]] || [[ $1 == "--local_compilers" ]]; then
        local="true"
    fi

    if [[ $1 == "-g" ]] || [[ $1 == "--compiler" ]]; then
        shift
        compiler="-g $1"
    fi

    if [[ $1 == "-n" ]] || [[ $1 == "--no-configure" ]]; then
        noconfigure="true"
    fi

    if [[ $1 == "-o" ]] || [[ $1 == "--out_of_tree" ]]; then
        shift
        out_of_tree="true"
        build_dir=$1
        hypervisor_dir=$PWD
    fi

    shift

done

# ------------------------------------------------------------------------------
# Setup System
# ------------------------------------------------------------------------------

case $(uname -r) in
2.5.*)
    install_common_packages
    setup_ewdk
    ;;

*)
    echo "This version of Cygwin is not supported"
    exit 1

esac

# ------------------------------------------------------------------------------
# Setup Build Environment
# ------------------------------------------------------------------------------

if [[ ! $local == "true" ]]; then
    echo "Docker currently not supported. Use -l to setup local compilers"
    exit 1
fi

if [[ ! $noconfigure == "true" ]]; then
    if [[ $out_of_tree == "true" ]]; then
        mkdir -p $build_dir
        pushd $build_dir
        $hypervisor_dir/configure.sh
        popd
    else
        ./configure.sh $compiler
    fi
fi

if [[ $local == "true" ]]; then
    CROSS_COMPILER=gcc_520 ./tools/scripts/create-cross-compiler.sh
fi

# ------------------------------------------------------------------------------
# Done
# ------------------------------------------------------------------------------

echo ""

echo "WARNING: If you are going to use this machine for testing, you must "
echo "         turn test signing on yourself:"
echo ""
echo "bcdedit.exe /set testsigning ON"
echo ""

if [[ $out_of_tree == "true" ]]; then
    echo "To build, run:"
    echo "    cd $build_dir"
    echo "    make -j<# cores>"
    echo ""
fi
