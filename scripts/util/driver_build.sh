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

msbuild_2015="/cygdrive/c/Program Files (x86)/MSBuild/14.0/Bin/MSBuild.exe"
msbuild_2017="/cygdrive/c/Program Files (x86)/Microsoft Visual Studio/2017/Community/MSBuild/15.0/bin/msbuild.exe"

find_msbuild() {

    if [[ -f $msbuild_2017 ]]; then
        msbuild=$msbuild_2017
        return
    fi

    if [[ -f $msbuild_2015 ]]; then
        msbuild=$msbuild_2015
        return
    fi

    >&2 echo "ERROR: failed to find msbuild"
    exit 1
}

case $(uname -s) in
CYGWIN_NT-6.1*)
    find_msbuild
    cd $1/src/platform/windows/
    >&2 eval "'$msbuild' /m:3 /p:Configuration=Release /p:Platform=x64 /p:TargetVersion=Windows7 bareflank.sln"
    ;;
CYGWIN_NT-6.3*)
    find_msbuild
    cd $1/src/platform/windows/
    >&2 eval "'$msbuild' /m:3 /p:Configuration=Release /p:Platform=x64 /p:TargetVersion=WindowsV6.3 bareflank.sln"
    ;;
CYGWIN_NT-10.0*)
    find_msbuild
    cd $1/src/platform/windows/
    >&2 eval "'$msbuild' /m:3 /p:Configuration=Release /p:Platform=x64 /p:TargetVersion=Windows10 bareflank.sln"
    ;;
Linux)
    cd $1/src/platform/linux
    make
    ;;
*)
    >&2 echo "OS not supported"
    exit 1
esac
