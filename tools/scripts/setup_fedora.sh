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

check_distro fedora
check_folder

# ------------------------------------------------------------------------------
# Parse Arguments
# ------------------------------------------------------------------------------

parse_arguments $@

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
# Setup System
# ------------------------------------------------------------------------------

case $( grep ^VERSION_ID= /etc/os-release | cut -d'=' -f 2 | tr -d '"' ) in
25)
    install_common_packages
    prepare_docker
    ;;

24)
    install_common_packages
    prepare_docker
    ;;

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

setup_build_environment

echo ""
echo "WARNING: Please reboot before attempting to compile / use Bareflank!!!"
echo ""
