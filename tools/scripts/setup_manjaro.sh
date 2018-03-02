#!/bin/bash -e
#
# Setup script for manjaro
#
# Copyright (C) 2017 Assured Information Security, Inc.
# Author: Connor Davis      <davisc@ainfosec.com>
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

check_distro manjaro
check_folder

# ------------------------------------------------------------------------------
# Parse Arguments
# ------------------------------------------------------------------------------

parse_arguments $@

# ------------------------------------------------------------------------------
# Functions
# ------------------------------------------------------------------------------

manjaro_headers() {
    major=`uname -r | cut -d '.' -f 1`
    minor=`uname -r | cut -d '.' -f 2`
    echo "linux$major$minor-headers"
}

install_common_packages() {
    sudo pacman -Syu
    sudo pacman -S --needed --noconfirm `manjaro_headers`
    sudo pacman -S --needed --noconfirm nasm
    sudo pacman -S --needed --noconfirm clang
    sudo pacman -S --needed --noconfirm texinfo
    sudo pacman -S --needed --noconfirm cmake
}


# ------------------------------------------------------------------------------
# Setup System
# ------------------------------------------------------------------------------

install_common_packages

# ------------------------------------------------------------------------------
# Setup Build Environment
# ------------------------------------------------------------------------------

setup_build_environment
