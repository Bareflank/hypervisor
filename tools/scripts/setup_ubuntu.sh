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

source $(dirname $0)/setup_common.sh

# ------------------------------------------------------------------------------
# Checks
# ------------------------------------------------------------------------------

check_distro ubuntu
check_folder

# ------------------------------------------------------------------------------
# Parse Arguments
# ------------------------------------------------------------------------------

parse_arguments $@

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
    sudo apt-get install --yes realpath
}

install_clang_1610() {
    sudo apt-get update
    sudo apt-get install --yes clang-3.8 clang++-3.8 clang-tidy-3.8
    sudo apt-get install --yes clang-3.9 clang++-3.9 clang-tidy-3.9
    sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-3.8 100
    sudo update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-3.8 100
    sudo update-alternatives --install /usr/bin/clang-tidy clang-tidy /usr/bin/clang-tidy-3.8 100
}

install_clang_1604() {
    wget http://llvm.org/releases/3.8.1/clang+llvm-3.8.1-x86_64-linux-gnu-ubuntu-16.04.tar.xz
    tar xf clang*
    sudo cp -R clang*/* /usr/local/
    rm -Rf clang*

    wget http://releases.llvm.org/3.9.1/clang+llvm-3.9.1-x86_64-linux-gnu-ubuntu-16.04.tar.xz
    tar xf clang*
    sudo cp -R clang*/* /usr/local/
    rm -Rf clang*
}

install_clang_1404() {
    wget http://releases.llvm.org/3.8.1/clang+llvm-3.8.1-x86_64-linux-gnu-ubuntu-14.04.tar.xz
    tar xf clang*
    sudo cp -R clang*/* /usr/local/
    rm -Rf clang*

    wget http://releases.llvm.org/3.9.0/clang+llvm-3.9.0-x86_64-linux-gnu-ubuntu-14.04.tar.xz
    tar xf clang*
    sudo cp -R clang*/* /usr/local/
    rm -Rf clang*
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

install_g++-5() {
    sudo apt-get update
    sudo apt-get install --yes gcc-5
    sudo apt-get install --yes g++-5
    sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-5 100
    sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-5 100
    sudo update-alternatives --install /usr/bin/gcov gcov /usr/bin/gcov-5 100
}

# ------------------------------------------------------------------------------
# Setup System
# ------------------------------------------------------------------------------

case $( grep ^VERSION_ID= /etc/os-release | cut -d'=' -f 2 | tr -d '"' ) in
16.10)
    install_common_packages
    install_clang_1610
    ;;

16.04)
    install_apt_tools
    install_common_packages
    install_clang_1604
    ;;

14.04)
    install_apt_tools
    add_cmake_repositories
    add_gcc_repositories
    install_common_packages
    install_g++-5
    install_clang_1404
    ;;

*)
    echo "This version of Ubuntu is not supported"
    exit 1

esac

# ------------------------------------------------------------------------------
# Setup Build Environment
# ------------------------------------------------------------------------------

setup_build_environment
