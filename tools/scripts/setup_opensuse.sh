#!/bin/bash -e
#
# Bareflank Hypervisor
#
# Copyright (C) 2015 Assured Information Security, Inc.
# Author: Rian Quinn        <quinnr@ainfosec.com>
# Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
# Author: Harry ten Berge   <htenberge@gmail.com>
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

check_distro opensuse
check_folder

# ------------------------------------------------------------------------------
# Parse Arguments
# ------------------------------------------------------------------------------

parse_arguments $@

# ------------------------------------------------------------------------------
# Functions
# ------------------------------------------------------------------------------

install_common_packages() {
    sudo zypper install -y gcc-c++
    sudo zypper install -y gcc5
    sudo zypper install -y gcc5-c++
    sudo zypper install -y gmp-devel
    sudo zypper install -y mpc-devel
    sudo zypper install -y mpfr-devel
    sudo zypper install -y isl-devel

    sudo zypper install -y python
    sudo zypper install -y cmake

    sudo zypper install -y nasm
    sudo zypper install -y clang
    sudo zypper install -y texinfo
    sudo zypper install -y glibc-devel-static
    sudo zypper install -y kernel-devel
    sudo zypper update -y kernel-default

    sudo rm /usr/bin/gcc
    sudo rm /usr/bin/g++
    sudo ln -s /usr/bin/gcc-5 /usr/bin/gcc
    sudo ln -s /usr/bin/g++-5 /usr/bin/g++
}

# ------------------------------------------------------------------------------
# Setup System
# ------------------------------------------------------------------------------

case $( grep ^VERSION_ID= /etc/os-release | cut -d'=' -f 2 | tr -d '"' ) in
42.2)
    install_common_packages
    ;;

*)
    echo "This version of openSUSE is not supported"
    exit 1

esac

# ------------------------------------------------------------------------------
# Setup Build Environment
# ------------------------------------------------------------------------------

setup_build_environment
