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

case $( grep ^ID= /etc/os-release | cut -d'=' -f 2 ) in
ubuntu)
    ;;
*)
    echo "This script can only be used with: Ubuntu"
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
    echo -e "Usage: setup_ubuntu.sh [OPTION]"
    echo -e "Sets up the system to compile / use Bareflank"
    echo -e ""
    echo -e "       --help                       show this help menu"
    echo -e "       --local_compilers            setup local cross compilers"
    echo -e "       --no-configure               skip the configure step"
    echo -e "       --compiler <dirname>         directory of cross compiler"
    echo -e "       --out_of_tree <dirname>      setup out of tree build"
    echo -e ""
}

# ------------------------------------------------------------------------------
# Functions
# ------------------------------------------------------------------------------

install_common_packages() {
    sudo apt-get update
    sudo apt-get install --yes build-essential
    sudo apt-get install --yes linux-headers-$(uname -r)
    sudo apt-get install --yes libgmp-dev
    sudo apt-get install --yes libmpc-dev
    sudo apt-get install --yes libmpfr-dev
    sudo apt-get install --yes flex
    sudo apt-get install --yes bison
    sudo apt-get install --yes nasm
    sudo apt-get install --yes texinfo
    sudo apt-get install --yes cmake
}

install_clang_1610() {
    sudo apt-get update
    sudo apt-get install --yes clang-3.8
    sudo apt-get install --yes clang++-3.8
    sudo apt-get install --yes clang-tidy-3.8
    sudo ln -s /usr/bin/clang-3.8 /usr/bin/clang
    sudo ln -s /usr/bin/clang++-3.8 /usr/bin/clang++
    sudo ln -s /usr/bin/clang-tidy-3.8 /usr/bin/clang-tidy
}

install_clang_1604() {
    wget http://llvm.org/releases/3.8.1/clang+llvm-3.8.1-x86_64-linux-gnu-ubuntu-16.04.tar.xz
    tar xf clang*
    sudo cp -R clang*/* /usr/local/
    rm -Rf clang*
}

install_clang_1404() {
    wget http://llvm.org/releases/3.8.1/clang+llvm-3.8.1-x86_64-linux-gnu-ubuntu-14.04.tar.xz
    tar xf clang*
    sudo cp -R clang*/* /usr/local/
    rm -Rf clang*
}

install_docker_1610() {
    sudo apt-get update
    sudo apt-get install --yes docker.io
}

install_docker_1604() {
    sudo apt-get install --yes apt-transport-https
    sudo apt-get install --yes ca-certificates

    sudo apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D
    sudo add-apt-repository "deb https://apt.dockerproject.org/repo ubuntu-xenial main"

    sudo apt-get update
    sudo DEBIAN_FRONTEND=noninteractive apt-get install --yes -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" docker-engine
}

install_docker_1404() {
    sudo apt-get install --yes apt-transport-https
    sudo apt-get install --yes ca-certificates

    sudo apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D
    sudo add-apt-repository "deb https://apt.dockerproject.org/repo ubuntu-trusty main"

    sudo apt-get update
    sudo DEBIAN_FRONTEND=noninteractive apt-get install --yes -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" docker-engine
}

prepare_docker() {
    sudo usermod -a -G docker $USER
    sudo service docker restart
}

install_apt_tools() {
    sudo apt-get update
    sudo apt-get install --yes software-properties-common
    sudo apt-get install --yes python-software-properties
}

add_cmake_repositories() {
    sudo add-apt-repository ppa:george-edison55/cmake-3.x -y
}

add_gcc_repositories() {
    sudo add-apt-repository ppa:ubuntu-toolchain-r/test -y
}

install_g++-6() {
    sudo apt-get update
    sudo apt-get install --yes gcc-snapshot
    sudo apt-get install --yes gcc-6
    sudo apt-get install --yes g++-6
    sudo rm /usr/bin/gcc
    sudo rm /usr/bin/g++
    sudo ln -s /usr/bin/gcc-6 /usr/bin/gcc
    sudo ln -s /usr/bin/g++-6 /usr/bin/g++
}

fix_linux_kernel() {
    sudo cp /lib/modules/$(uname -r)/build/include/linux/compiler-gcc5.h /lib/modules/$(uname -r)/build/include/linux/compiler-gcc6.h || true
}

# ------------------------------------------------------------------------------
# Arguments
# ------------------------------------------------------------------------------

while [[ $# -ne 0 ]]; do

    if [[ $1 == "--help" ]]; then
        option_help
        exit 0
    fi

    if [[ $1 == "--local_compilers" ]]; then
        local="true"
    fi

    if [[ $1 == "--compiler" ]]; then
        shift
        compiler="--compiler $1"
    fi

    if [[ $1 == "--use_llvm_clang" ]]; then
        use_llvm_clang="--use_llvm_clang"
    fi

    if [[ $1 == "--no-configure" ]]; then
        noconfigure="true"
    fi

    if [[ $1 == "--out_of_tree" ]]; then
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

case $( grep ^VERSION_ID= /etc/os-release | cut -d'=' -f 2 | tr -d '"' ) in
16.10)
    install_common_packages
    install_clang_1610
    install_docker_1610
    prepare_docker
    ;;

16.04)
    install_common_packages
    install_clang_1604
    install_docker_1604
    prepare_docker
    ;;

14.04)
    install_apt_tools
    add_cmake_repositories
    add_gcc_repositories
    install_common_packages
    install_g++-6
    install_clang_1404
    install_docker_1404
    prepare_docker
    fix_linux_kernel
    ;;

*)
    echo "This version of Ubuntu is not supported"
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
    CROSS_COMPILER=gcc_520 ./tools/scripts/create_cross_compiler.sh
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
