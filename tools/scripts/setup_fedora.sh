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

sudo dnf install -y redhat-lsb-core

# ------------------------------------------------------------------------------
# Checks
# ------------------------------------------------------------------------------

case $(lsb_release -si) in
Fedora)
    ;;
*)
    echo "This script can only be used with: Fedora"
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
    echo -e "Usage: setup_fedora.sh [OPTION]"
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
    sudo dnf groupinstall -y "Development Tools"
    sudo dnf install -y gcc-c++
    sudo dnf install -y gmp-devel
    sudo dnf install -y libmpc-devel
    sudo dnf install -y mpfr-devel
    sudo dnf install -y isl-devel
    sudo dnf install -y cmake
    sudo dnf install -y nasm
    sudo dnf install -y clang
    sudo dnf install -y texinfo
    sudo dnf install -y libstdc++-static
    sudo dnf install -y kernel-devel
    sudo dnf install -y kernel-headers
    sudo dnf update -y kernel
    curl -fsSL https://get.docker.com/ | sh
}

prepare_docker() {
    sudo usermod -a -G docker $USER
    sudo systemctl start docker
    sudo systemctl enable docker
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

    if [[ $1 == "--compiler" ]]; then
        shift
        compiler="--compiler $1"
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

# ------------------------------------------------------------------------------
# Setup System
# ------------------------------------------------------------------------------

case $(lsb_release -sr) in
23)
    install_common_packages
    prepare_docker
    ;;

*)
    echo "This version of Fedora is not supported"
    exit 1

esac

# ------------------------------------------------------------------------------
# Setup Build Environment
# ------------------------------------------------------------------------------

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

if [[ $local == "true" ]]; then
    CROSS_COMPILER=clang_38 ./tools/scripts/create_cross_compiler.sh
fi

# ------------------------------------------------------------------------------
# Done
# ------------------------------------------------------------------------------

echo ""

echo "WARNING: A reboot is required to build!!!"
echo ""

if [[ $out_of_tree == "true" ]]; then
    echo "To build, run:"
    echo "    cd $build_dir"
    echo "    make -j<# cores>"
    echo ""
fi
