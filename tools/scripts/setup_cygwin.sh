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

if ! grep -q 'avx' /proc/cpuinfo; then
    echo "Hardware unsupported. AVX is required"
    exit 1
fi

# ------------------------------------------------------------------------------
# Help
# ------------------------------------------------------------------------------

option_help() {
    echo -e "Usage: setup_cygwin.sh [OPTION]"
    echo -e "Sets up the system to compile / use Bareflank"
    echo -e ""
    echo -e "       -h, --help                       show this help menu"
    echo -e "       -l, --local_compilers            setup local cross compilers"
    echo -e "       -n, --no-configure               skip the configure step"
    echo -e "       -g, --compiler <dirname>         directory of cross compiler"
    echo -e "       -o, --out_of_tree <dirname>      setup out of tree build"
    echo -e ""
}

# ------------------------------------------------------------------------------
# Functions
# ------------------------------------------------------------------------------

install_common_packages() {
    setup-x86_64.exe -q --wait -P wget,make,gcc-core,gcc-g++,diffutils,libgmp-devel,libmpfr-devel,libmpc-devel,flex,bison,nasm,texinfo,unzip,git-completion,bash-completion,patch,ncurses,libncurses-devel,clang
}

install_cmake() {
    rm -Rf cmake-*
    wget https://cmake.org/files/v3.6/cmake-3.6.2.tar.gz
    tar xf cmake-*
    pushd cmake-*
    ./configure
    make
    make install
    popd
    rm -Rf cmake-*
}

setup_ewdk() {
    if [[ ! -d /cygdrive/c/ewdk ]]; then
        wget -nv -O /tmp/ewdk.zip "https://go.microsoft.com/fwlink/p/?LinkID=699461"
        unzip -qq /tmp/ewdk.zip -d /cygdrive/c/ewdk/
        chown -R $USER:SYSTEM /cygdrive/c/ewdk
        icacls.exe `cygpath -w /cygdrive/c/ewdk` /reset /T /Q
        rm -Rf /tmp/ewdk.zip
    fi
}

setup_cross_compilers() {
    if [[ ! -f $HOME/bareflank_windows_cross_compilers.tar.gz ]]; then
        wget -nv -O $HOME/bareflank_windows_cross_compilers.tar.gz "http://138.68.60.235/bareflank_windows_cross_compilers.tar.gz"
    fi
    if [[ ! -d $HOME/compilers ]]; then
        pushd $HOME
        tar xf bareflank_windows_cross_compilers.tar.gz compilers
        popd
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
        local_compilers="true"
    fi

    if [[ $1 == "-d" ]] || [[ $1 == "--download_compilers" ]]; then
        download_compilers="true"
    fi

    if [[ $1 == "--compiler" ]]; then
        shift
        compiler="--compiler $1"
    fi

    if [[ $1 == "--no_ewdk" ]]; then
        no_ewdk="true"
    fi

    if [[ $1 == "--use_llvm_clang" ]]; then
        use_llvm_clang="--use_llvm_clang"
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

if [[ ! $download_compilers == "true" ]]; then
    echo "Docker currently not supported. Use -d to download local compilers"
    exit 1
fi

# ------------------------------------------------------------------------------
# Setup System
# ------------------------------------------------------------------------------

case $(uname -r) in
2.6.*)
    install_common_packages
    install_cmake
    if [[ ! $no_ewdk == "true" ]]; then setup_ewdk; fi
    ;;

2.5.*)
    install_common_packages
    install_cmake
    if [[ ! $no_ewdk == "true" ]]; then setup_ewdk; fi
    ;;

*)
    echo "This version of Cygwin is not supported"
    exit 1

esac

# ------------------------------------------------------------------------------
# Setup Build Environment
# ------------------------------------------------------------------------------

if [[ $local_compilers == "true" ]]; then
    echo "Setting up local compilers"
    CROSS_COMPILER=clang_38 ./tools/scripts/create_cross_compiler.sh
fi

if [[ $download_compilers == "true" ]]; then
    echo "Downloading local compilers"
    setup_cross_compilers
fi

if [[ ! $noconfigure == "true" ]]; then
    if [[ $out_of_tree == "true" ]]; then
        mkdir -p $build_dir
        pushd $build_dir
        $hypervisor_dir/configure
        popd
    else
        ./configure $compiler $use_llvm_clang
    fi
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
