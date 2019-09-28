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

certmgr_10_0_00000_0="/cygdrive/c/Program Files (x86)/Windows Kits/10/bin/x64/certmgr"
certmgr_10_0_18362_0="/cygdrive/c/Program Files (x86)/Windows Kits/10/bin/10.0.18362.0/x64/certmgr"
certmgr_10_0_17763_0="/cygdrive/c/Program Files (x86)/Windows Kits/10/bin/10.0.17763.0/x64/certmgr"
certmgr_10_0_17134_0="/cygdrive/c/Program Files (x86)/Windows Kits/10/bin/10.0.17134.0/x64/certmgr"
certmgr_10_0_16299_0="/cygdrive/c/Program Files (x86)/Windows Kits/10/bin/10.0.16299.0/x64/certmgr"
certmgr_10_0_15063_0="/cygdrive/c/Program Files (x86)/Windows Kits/10/bin/10.0.15063.0/x64/certmgr"
certmgr_10_0_14393_0="/cygdrive/c/Program Files (x86)/Windows Kits/10/bin/10.0.14393.0/x64/certmgr"

find_certmgr() {

    if [[ -f $certmgr_10_0_00000_0 ]]; then
        certmgr=$certmgr_10_0_00000_0
        return
    fi

    if [[ -f $certmgr_10_0_18362_0 ]]; then
        certmgr=$certmgr_10_0_18362_0
        return
    fi

    if [[ -f $certmgr_10_0_17763_0 ]]; then
        certmgr=$certmgr_10_0_17763_0
        return
    fi

    if [[ -f $certmgr_10_0_17134_0 ]]; then
        certmgr=$certmgr_10_0_17134_0
        return
    fi

    if [[ -f $certmgr_10_0_16299_0 ]]; then
        certmgr=$certmgr_10_0_16299_0
        return
    fi

    if [[ -f $certmgr_10_0_15063_0 ]]; then
        certmgr=$certmgr_10_0_15063_0
        return
    fi

    if [[ -f $certmgr_10_0_14393_0 ]]; then
        certmgr=$certmgr_10_0_14393_0
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
