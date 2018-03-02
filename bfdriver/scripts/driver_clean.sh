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

case $(uname -s) in
CYGWIN_NT*)
    rm -Rf $1/src/arch/windows/.vs/
    rm -Rf $1/src/arch/windows/bareflank.VC.db
    rm -Rf $1/src/arch/windows/x64/
    ;;
Linux)
    cd $1/src/arch/linux
    make clean
    ;;
*)
    >&2 echo "OS not supported"
    exit 1
esac
