#!/bin/bash -e
#
# Bareflank Hypervisor
# Copyright (C) 2015 Assured Information Security, Inc.
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

# $1 == CMAKE_SOURCE_DIR
# $2 == CMAKE_INSTALL_PREFIX

case $(uname -s) in
Linux)
    #echo $1 $2
    make SYSROOT="$2" MODULES="$3" -C $1/src/platform/efi/ modules
    make SYSROOT="$2" MODULES="$3" -C $1/src/platform/efi/ all
    ;;
*)
    >&2 echo "OS not supported"
    exit 1
esac
