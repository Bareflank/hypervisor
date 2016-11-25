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

check_distro debian
check_folder
check_hardware

# ------------------------------------------------------------------------------
# Parse Arguments
# ------------------------------------------------------------------------------

parse_arguments $@

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
# Setup System
# ------------------------------------------------------------------------------

case $( grep ^VERSION_ID= /etc/os-release | cut -d'=' -f 2 | tr -d '"' ) in
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

setup_build_environment
