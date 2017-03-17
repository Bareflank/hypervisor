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
    sudo apt-get install --yes nasm
    sudo apt-get install --yes texinfo
    sudo apt-get install --yes realpath
    sudo apt-get install --yes clang
    sudo apt-get install --yes clang++
}

# ------------------------------------------------------------------------------
# Setup System
# ------------------------------------------------------------------------------

case $( grep ^VERSION_ID= /etc/os-release | cut -d'=' -f 2 | tr -d '"' ) in
17.10)
    install_common_packages
    ;;

17.04)
    install_common_packages
    ;;

16.10)
    install_common_packages
    ;;

*)
    echo "This version of Ubuntu is not supported"
    exit 1

esac

# ------------------------------------------------------------------------------
# Setup Build Environment
# ------------------------------------------------------------------------------

setup_build_environment
