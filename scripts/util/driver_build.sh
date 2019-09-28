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

# $1 == CMAKE_SOURCE_DIR
# $2 == CMAKE_INSTALL_PREFIX

msbuild_2015="/cygdrive/c/Program Files (x86)/MSBuild/14.0/Bin/MSBuild.exe"
msbuild_2017="/cygdrive/c/Program Files (x86)/Microsoft Visual Studio/2017/Community/MSBuild/15.0/bin/msbuild.exe"
msbuild_2019="/cygdrive/c/Program Files (x86)/Microsoft Visual Studio/2019/Community/MSBuild/current/bin/msbuild.exe"

find_msbuild() {

    if [[ -f $msbuild_2019 ]]; then
        msbuild=$msbuild_2019
        return
    fi

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
