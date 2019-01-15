#!/bin/bash -e
#
# Copyright (C) 2019 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

VAGRANT_BUILD_DIR="/vagrant/build_ubuntu17_10"
VAGRANT_HOME_DIR="/home/ubuntu"

sudo apt-get update
sudo apt-get install -y git build-essential linux-headers-$(uname -r) clang \
    binutils-aarch64-linux-gnu gcc-aarch64-linux-gnu nasm cmake clang-tidy-4.0 \
    cmake-curses-gui astyle

# Have 'vagrant ssh' bring you straight to a build directory
echo "mkdir -p $VAGRANT_BUILD_DIR && cd $VAGRANT_BUILD_DIR" >> $VAGRANT_HOME_DIR/.profile
