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

%ENV_SOURCE%

case $(uname -s) in
CYGWIN_NT-6.3)
    rm -Rf $BUILD_ABS/outdir
    rm -Rf $BUILD_ABS/intdir
    SCRIPT_PATH=`cygpath -w $HYPER_ABS/tools/scripts/build_windows.bat`
    HYPER_ABS_PATH=`cygpath -w $HYPER_ABS`
    BUILD_ABS_PATH=`cygpath -w $BUILD_ABS`
    cmd.exe /c $SCRIPT_PATH $HYPER_ABS_PATH $BUILD_ABS_PATH WindowsV6.3
    ;;

CYGWIN_NT-10.0)
    rm -Rf $BUILD_ABS/outdir
    rm -Rf $BUILD_ABS/intdir
    SCRIPT_PATH=`cygpath -w $HYPER_ABS/tools/scripts/build_windows.bat`
    HYPER_ABS_PATH=`cygpath -w $HYPER_ABS`
    BUILD_ABS_PATH=`cygpath -w $BUILD_ABS`
    cmd.exe /c $SCRIPT_PATH $HYPER_ABS_PATH $BUILD_ABS_PATH Windows10
    ;;

Linux)
    cd $HYPER_ABS/bfdrivers/src/arch/linux
    make clean
    make
    ;;
*)
    echo "OS not supported"
    exit 1
esac
