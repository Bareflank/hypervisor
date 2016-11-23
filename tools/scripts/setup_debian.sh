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

case $(lsb_release -si) in
Debian)
    ;;
*)
    echo "This script can only be used with: Debian"
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
    echo -e "Usage: setup_debian.sh [OPTION]"
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

install_apt_tools() {
    sudo apt-get update
    sudo apt-get install --yes software-properties-common
    sudo apt-get install --yes apt-transport-https
    sudo apt-get install --yes ca-certificates
}

add_docker_repositories() {
    sudo apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D
    sudo add-apt-repository "deb https://apt.dockerproject.org/repo debian-$(lsb_release -s -c) main"
}

install_common_packages() {
    sudo apt-get update
    sudo apt-get install --yes build-essential
    sudo apt-get install --yes linux-headers-amd64
    sudo apt-get install --yes linux-image-amd64
    sudo apt-get install --yes libgmp-dev
    sudo apt-get install --yes libmpc-dev
    sudo apt-get install --yes libmpfr-dev
    sudo apt-get install --yes flex
    sudo apt-get install --yes bison
    sudo apt-get install --yes nasm
    sudo apt-get install --yes clang
    sudo apt-get install --yes texinfo
    sudo apt-get install --yes cmake
    sudo DEBIAN_FRONTEND=noninteractive apt-get install --yes -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" docker-engine
}

prepare_docker() {
    sudo usermod -a -G docker $USER
    sudo service docker restart
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
testing)
    install_apt_tools
    add_docker_repositories
    install_common_packages
    prepare_docker
    ;;

*)
    echo "This version of Debian is not supported"
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

echo "WARNING: If you are using ssh, or are logged into a GUI you "
echo "         might need to exit and log back in to compile!!!"
echo ""

if [[ $out_of_tree == "true" ]]; then
    echo "To build, run:"
    echo "    cd $build_dir"
    echo "    make -j<# cores>"
    echo ""
fi
