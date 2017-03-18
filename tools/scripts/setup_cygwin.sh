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

check_distro Cygwin
check_folder

# ------------------------------------------------------------------------------
# Parse Arguments
# ------------------------------------------------------------------------------

parse_arguments $@

# ------------------------------------------------------------------------------
# Functions
# ------------------------------------------------------------------------------

install_common_packages() {
    setup-x86_64.exe -q --wait -P make,gcc-core,gcc-g++,diffutils,libgmp-devel,libmpfr-devel,libmpc-devel,flex,bison,nasm,texinfo,unzip,git-completion,bash-completion,patch,ncurses,libncurses-devel,clang,clang++,libiconv-devel,curl,wget
}

install_cmake() {
    rm -Rf cmake-*
    curl -L -o cmake-3.6.2.tar.gz https://cmake.org/files/v3.6/cmake-3.6.2.tar.gz
    tar xf cmake-*
    pushd cmake-3.6.2
    ./configure
    make
    make install
    popd
    rm -Rf cmake-*
}

setup_ewdk() {
    if [[ ! -d /cygdrive/c/ewdk ]]; then
        echo "Fetching EWDK. Please wait..."
        curl "https://go.microsoft.com/fwlink/p/?LinkID=699461" -L --output /tmp/ewdk.zip
        echo "Installing EWDK. Please wait..."
        unzip -qq /tmp/ewdk.zip -d /cygdrive/c/ewdk/
        chown -R $USER:SYSTEM /cygdrive/c/ewdk
        icacls.exe `cygpath -w /cygdrive/c/ewdk` /reset /T /Q
        rm -Rf /tmp/ewdk.zip
    fi
}

# ------------------------------------------------------------------------------
# Setup System
# ------------------------------------------------------------------------------

case $(uname -r) in
2.7.*)
    install_common_packages
    install_cmake
    setup_ewdk
    ;;

2.6.*)
    install_common_packages
    install_cmake
    setup_ewdk
    ;;

2.5.*)
    install_common_packages
    install_cmake
    setup_ewdk
    ;;

*)
    echo "This version of Cygwin is not supported"
    exit 1

esac

# ------------------------------------------------------------------------------
# Setup Build Environment
# ------------------------------------------------------------------------------

./$(dirname $0)/build_binutils.sh

# ------------------------------------------------------------------------------
# Setup Build Environment
# ------------------------------------------------------------------------------

setup_build_environment

echo ""
echo "WARNING: Please turn test signing on before attempting to compile / user Bareflank! 'bcdedit.exe /set testsigning ON' --> <reboot>"
echo ""
