#!/bin/bash -e
#
# Bareflank Hypervisor
# Copyright (C) 2018 Assured Information Security, Inc.
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

VAGRANT_BUILD_DIR="/vagrant/build_ubuntu17_10"
VAGRANT_HOME_DIR="/home/ubuntu"

sudo apt-get update
sudo apt-get install -y git build-essential linux-headers-$(uname -r) clang \
    binutils-aarch64-linux-gnu gcc-aarch64-linux-gnu nasm cmake clang-tidy-4.0 \
    cmake-curses-gui astyle

# Have 'vagrant ssh' bring you straight to a build directory
echo "mkdir -p $VAGRANT_BUILD_DIR && cd $VAGRANT_BUILD_DIR" >> $VAGRANT_HOME_DIR/.profile
