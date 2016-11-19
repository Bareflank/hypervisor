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

check_distro() {
    case $( grep ^ID= /etc/os-release | cut -d'=' -f 2 ) in
    $1)
        ;;
    *)
        echo "This script can only be used with: $1"
        exit 1
    esac
}

check_folder() {
    if [[ ! -d "bfelf_loader" ]]; then
        echo "This script must be run from bareflank root directory"
        exit 1
    fi
}

check_hardware() {
    if ! grep -q 'avx' /proc/cpuinfo; then
        echo "Hardware unsupported. AVX is required"
        exit 1
    fi
}

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
# Arguments
# ------------------------------------------------------------------------------

build_dir=$PWD
hypervisor_dir=$PWD

parse_arguments() {
    while [[ $# -ne 0 ]]; do

        case $1 in
        "--help")
            option_help
            exit 0
            ;;

        "--local_compilers")
            local="true"
            ;;

        "--compiler")
            shift
            compiler="--compiler $1"
            ;;

        "--no-configure")
            noconfigure="true"
            ;;

        "--out_of_tree")
            shift
            build_dir=$1
            mkdir -p $build_dir
            ;;

        *)
            echo "unknown option: $1"
            exit 1
        esac

        shift

    done
}

# ------------------------------------------------------------------------------
# Setup Build Environment
# ------------------------------------------------------------------------------

setup_build_environment() {
    if [[ ! $noconfigure == "true" ]]; then
        pushd $build_dir
        $hypervisor_dir/configure $compiler
        popd
    fi

    if [[ $local == "true" ]]; then
        CROSS_COMPILER=clang_38 ./tools/scripts/create_cross_compiler.sh
    fi

    echo ""
    echo "WARNING: If you are using ssh, or are logged into a GUI you "
    echo "         might need to exit and log back in to compile!!!"
    echo ""
}
