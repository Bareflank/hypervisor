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

# $1 == CMAKE_SOURCE_DIR

certmgr_10_0_00000_0="/cygdrive/c/Program Files (x86)/Windows Kits/10/bin/x64/certmgr"
certmgr_10_0_17134_0="/cygdrive/c/Program Files (x86)/Windows Kits/10/bin/10.0.17134.0/x64/certmgr"

find_certmgr() {

    if [[ -f $certmgr_10_0_17134_0 ]]; then
        certmgr=$certmgr_10_0_17134_0
        return
    fi

    if [[ -f $certmgr_10_0_00000_0 ]]; then
        certmgr=$certmgr_10_0_00000_0
        return
    fi

    >&2 echo "ERROR: failed to find certmgr"
    exit 1
}

case $(uname -s) in
CYGWIN_NT*)
    find_certmgr
    cd $1/src/platform/windows
    >&2 eval "'$certmgr' /add x64/Release/bareflank.cer /s /r localMachine root"
    >&2 eval "'$certmgr' /add x64/Release/bareflank.cer /s /r localMachine trustedpublisher"
    >&2 /cygdrive/c/Program\ Files\ \(x86\)/Windows\ Kits/10/Tools/x64/devcon remove "ROOT\bareflank"
    >&2 /cygdrive/c/Program\ Files\ \(x86\)/Windows\ Kits/10/Tools/x64/devcon install x64/Release/bareflank/bareflank.inf "ROOT\bareflank"
    ;;
Linux)
    cd $1/src/platform/linux
    sudo make unload 1> /dev/null 2> /dev/null
    sudo make load 1> /dev/null 2> /dev/null
    ;;
*)
    >&2 echo "OS not supported"
    exit 1
esac
